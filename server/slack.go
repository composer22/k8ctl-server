package server

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/slack-go/slack"
)

// NewSlackWorker handles Real Time Messaging from Slack bot.
type slackWorker struct {
	api  *slack.Client // Slack api manager.
	rtm  *slack.RTM    // Slack real time messager manager.
	srvr *Server       // Parent server for callback functions.
}

// NewWorker is a factory function that returns a worker object.
func NewSlackWorker(sv *Server) (*slackWorker, error) {
	// Retrieve the slack token from AWS.
	t, err := sv.ssmsvc.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(sv.opt.SlackAPITokenPath),
			WithDecryption: aws.Bool(true),
		})
	if err != nil {
		sv.log.Errorf("Unable to retrieve Jenkins token. Error: %s", err.Error())
		return nil, err
	}
	a := slack.New(aws.StringValue(t.Parameter.Value))
	return &slackWorker{
		api:  a,
		rtm:  a.NewRTM(),
		srvr: sv,
	}, nil
}

// Run is the main event loop that processes real time events from Slack for the bot.
func (l *slackWorker) Run() {
	go l.rtm.ManageConnection()
	for msg := range l.rtm.IncomingEvents {
		switch ev := msg.Data.(type) {
		case *slack.ConnectedEvent:
			for _, c := range l.srvr.opt.SlackChannelIDs {
				l.rtm.SendMessage(l.rtm.NewOutgoingMessage("Howdy. I'm ready to accept deploys.", c))
			}
		case *slack.MessageEvent:
			if err := l.handleMessageEvent(ev); err != nil {
				l.srvr.log.Errorf("Failed to handle message: %s", err)
				l.rtm.SendMessage(l.rtm.NewOutgoingMessage(err.Error(), ev.Channel))
			}
		default:
		}
	}
}

// Signal shutdown to all channels
func (l *slackWorker) RunDone() {
	for _, c := range l.srvr.opt.SlackChannelIDs {
		l.rtm.SendMessage(l.rtm.NewOutgoingMessage("Gotta run. Signing off. G'bye.", c))
	}
	time.Sleep(time.Duration(10) * time.Second) // pause a bit so msgs can be ingested.
}

// handleMessageEvent - processes the event received in the chat to see if it is actionable.
// If so, prompts the user with a dialog for deploy.
func (l *slackWorker) handleMessageEvent(ev *slack.MessageEvent) error {
	auth, err := l.api.AuthTest()
	if err != nil {
		errors.New("Could not validate bot. Contact ops.")
	}

	// Only response mention to bot. Ignore else.
	if !strings.HasPrefix(ev.Msg.Text, fmt.Sprintf("<@%s> ", auth.UserID)) {
		return nil
	}

	// Only respond in specific channels. Ignore all others. Tell user where to go.
	if err := l.validateChannel(ev.Channel); err != nil {
		return err
	}

	// Parse message
	m := strings.Split(strings.TrimSpace(ev.Msg.Text), " ")[1:]
	if len(m) == 0 || (m[0] != "deploy" && m[0] != "form") {
		return errors.New("I don't understand your jibberish! More of your conversation would infect my brain. Try typing 'deploy' to get the deploy form if you're brave enough.")
	}
	action := m[0]

	// Does the user have a right to deploy? Validate against ssm.
	if err := l.validateUserAuth(ev.User); err != nil {
		return err
	}

	switch action {
	case "deploy": // Send interactive prompt to channel.
		var blk slack.MsgOption
		blk, err = l.formBlockPrologue()
		if err != nil {
			return errors.New("Could not render deploy form. Contact ops.")
		}
		if _, _, err := l.rtm.PostMessage(ev.Channel, slack.MsgOptionAsUser(true), blk); err != nil {
			l.srvr.log.Errorf("PostMessage: %s", err.Error())
			return errors.New("Could not send deploy form. Contact ops.")
		}
	}
	return nil
}

// Is the message in a channel we are monitoring?
func (l *slackWorker) validateChannel(channel string) error {
	i, err := l.rtm.GetConversationInfo(channel, true)
	if err != nil {
		l.srvr.log.Errorf("Could not find conversation info for users channel id: %s", channel)
		return errors.New("Sorry. Internal error finding your channel information. Contact ops admin.")
	}
	userChannelName := i.Name
	var chList string
	for _, ch := range l.srvr.opt.SlackChannelIDs {
		if ch == channel {
			return nil // Found. We are good.
		}
		// Add the unmatched valid channel name to send the user, in the case the whole test fails.
		i, err = l.rtm.GetConversationInfo(ch, true)
		if err != nil {
			l.srvr.log.Errorf("Could not find conversation info for channel id: %s", ch)
			return errors.New("Sorry. Internal error finding channel information Contact ops admin.")
		}
		chList += fmt.Sprintf("#%s\n", i.Name)
	}
	return errors.New(fmt.Sprintf("Sorry. Cannot receive a formal request from channel \"%s.\"\nPlease try an official channel:\n%s", userChannelName, chList))
}

// Does the user have an authority to perform deploys?
func (l *slackWorker) validateUserAuth(userID string) error {
	// Look user up in slack to get the email address.
	u, err := l.rtm.GetUserInfo(userID)
	if err != nil {
		return errors.New("Sorry. Your user id could not be found. Please contact administrator.")
	}
	if u.Profile.Email == "" {
		return errors.New("Sorry. Your profile's email could not be found. Please contact administrator.")
	}

	// Validate authority in ssm.
	var params []*ssm.Parameter
	params, err = l.getParamsByPath(l.srvr.opt.AuthPathPrefix)
	if err != nil {
		return errors.New("Sorry. System had trouble authenticating. Please contact administrator.")
	}
	// Look for email value match.
	for _, param := range params {
		if strings.Contains(aws.StringValue(param.Name), "email") && (aws.StringValue(param.Value) == u.Profile.Email) {
			return nil
		}
	}
	return errors.New("Sorry. You do not have authority to perform slack actions. Please contact administrator.")
}

// getParamsByPath - search subpath for all keys and return decrypted results. Filter by keyword option.
func (l *slackWorker) getParamsByPath(path string) ([]*ssm.Parameter, error) {
	params := make([]*ssm.Parameter, 0)
	var nextToken string
	for {
		input := &ssm.GetParametersByPathInput{
			Path:           aws.String(path),
			Recursive:      aws.Bool(true),
			WithDecryption: aws.Bool(true),
		}

		if nextToken != "" {
			input.SetNextToken(nextToken)
		}

		result, err := l.srvr.ssmsvc.GetParametersByPath(input)
		if err != nil {
			return nil, err
		}
		params = append(params, result.Parameters...)

		// Paging?
		if result.NextToken != nil {
			nextToken = *result.NextToken
		} else {
			break
		}
	}
	return params, nil
}

// formBlockPrologue - gives the user the first instructions on performing a deployment using the form method.
func (l *slackWorker) formBlockPrologue() (slack.MsgOption, error) {
	// Instructions
	instructions := `
:pizza: Welcome to the deployment process. Make sure you know which repo and tag you wish to deploy.
Press the *start* button to launch the deployment form. Or, press the *cancel* button to stop.
`

	instructionTxt := slack.NewTextBlockObject("mrkdwn", instructions, false, false)
	instructionSection := slack.NewSectionBlock(instructionTxt, nil, nil)

	// submit Button
	startBtn := slack.NewButtonBlockElement("start_01", "start", slack.NewTextBlockObject("plain_text", "Start...", false, false))
	cancelBtn := slack.NewButtonBlockElement("cancel_01", "cancel", slack.NewTextBlockObject("plain_text", "Cancel", false, false))
	actionBlock := slack.NewActionBlock("", startBtn, cancelBtn)

	// Build Message with blocks created above.
	msgBlock := slack.MsgOptionBlocks(
		instructionSection,
		actionBlock,
	)
	return msgBlock, nil
}

// deployModal - creates a modal dialog to ask the user for the deployment parameters.
func (l *slackWorker) deployModal() (slack.ModalViewRequest, error) {
	var modalRequest slack.ModalViewRequest

	// Common text to assign to modal.
	titleText := slack.NewTextBlockObject("plain_text", ":pizza: Deploy a Repo", false, false)
	closeText := slack.NewTextBlockObject("plain_text", "Close", false, false)
	submitText := slack.NewTextBlockObject("plain_text", "Submit", false, false)

	// Header
	headerText := slack.NewTextBlockObject("plain_text",
		"Please fill out the form with the mandatory values. Then press 'Submit' to send a deploy request to Jenkins.", false, false)
	headerSection := slack.NewSectionBlock(headerText, nil, nil)

	// Choose namespace.
	var namespaceObjects []*slack.OptionBlockObject
	for _, n := range l.srvr.opt.Namespaces {
		o := slack.NewOptionBlockObject(n, slack.NewTextBlockObject("plain_text", n, false, false))
		namespaceObjects = append(namespaceObjects, o)
	}
	namespaceTxt := slack.NewTextBlockObject("plain_text", "Namespace", false, false)
	namespaceOptions := slack.NewOptionsSelectBlockElement("static_select", namespaceTxt, "namespaceSelected", nil)
	namespaceOptions.Options = namespaceObjects
	namespace := slack.NewInputBlock("namespaceSelected", namespaceTxt, namespaceOptions)

	// Choose Repo.
	var repos []string
	var err error
	if repos, err = l.srvr.getValidApps(l.srvr.opt.ValidAppsDeployPath); err != nil {
		l.srvr.log.Errorf("Apps: %s", err.Error())
		return modalRequest, err
	}
	sort.Strings(repos)
	var repoObjects []*slack.OptionBlockObject
	for _, r := range repos {
		o := slack.NewOptionBlockObject(r, slack.NewTextBlockObject("plain_text", r, false, false))
		repoObjects = append(repoObjects, o)
	}
	repoTxt := slack.NewTextBlockObject("plain_text", "Repo", false, false)
	repoOptions := slack.NewOptionsSelectBlockElement("static_select", repoTxt, "repoSelected", nil)
	repoOptions.Options = repoObjects
	repo := slack.NewInputBlock("repoSelected", repoTxt, repoOptions)

	// Enter Tag
	tagTxt := slack.NewTextBlockObject("plain_text", "Image Tag", false, false)
	tagHelp := fmt.Sprintf("Enter the repo image tag. Must start w/ '%s'", l.srvr.opt.ImageTagPrefix)
	tagPlaceholder := slack.NewTextBlockObject("plain_text", tagHelp, false, false)
	tagElement := slack.NewPlainTextInputBlockElement(tagPlaceholder, "imageTag")
	tag := slack.NewInputBlock("imageTag", tagTxt, tagElement)

	// Optional Memo
	memoTxt := slack.NewTextBlockObject("plain_text", "Memo", false, false)
	memoPlaceholder := slack.NewTextBlockObject("plain_text", "Enter any descriptive info for this deploy.", false, false)
	memoElement := slack.NewPlainTextInputBlockElement(memoPlaceholder, "memo")
	memo := slack.NewInputBlock("memo", memoTxt, memoElement)

	// Final format of payload.
	blocks := slack.Blocks{
		BlockSet: []slack.Block{
			headerSection,
			namespace,
			repo,
			tag,
			memo,
		},
	}
	modalRequest.Type = slack.ViewType("modal")
	modalRequest.Title = titleText
	modalRequest.Close = closeText
	modalRequest.Submit = submitText
	modalRequest.Blocks = blocks
	return modalRequest, nil
}
