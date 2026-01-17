// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	"fmt"

	"github.com/cylonix/utils"
)

const (
	externalInviteEmailBody = `
<p>Hello,</p>
<h3 style="margin: 20px; text-align: center">
	You are invited to join a Cylonix network.
</h3>

<p style="margin: 20px; text-align: center">
	%s has invited you to join %s Cylonix network. You can use Cylonix to
	securely share devices and services.
</p>

<p style="margin: 20px; text-align: center">
	Please click the link below to accept the invitation.
	Then sign in with your preferred identity provider,
	and install Cylonix on your device to join the Cylonix network.
</p>

<p style="margin: 20px; text-align: center">
	<a href="%s" target="_blank">
		Join Cylonix Network
	</a>
</p>

<p style="margin: 20px; text-align: center; font-size: 80%%">
	Need help getting started? Checkout our documentation at
	<a href="%s" target="_blank">%s</a>,
	or reply to this email to talk to our support team.
</p>

<p>Best regards,</p>
<p>Cylonix Team</p>
<br></br>

<p style="font-size: 80%%">
	Does this email look suspicious or you don't recognize
	the sender? Report abuse by emailing to %s
</p>
`

	internalWelcomeEmailBody = `
<p>Hello,</p>
<h3 style="margin: 20px; text-align: center">
	Welcome to join the Cylonix network.
</h3>

<p style="margin: 20px; text-align: center">
	%s has invited you to join %s Cylonix network. You can use Cylonix to
	securely share devices and services.
</p>

<p style="margin: 20px; text-align: center">
	Please click the link below to accept the invitation.
	Then sign in with your organization's sign-in provider,
	and install Cylonix on your device to be part of the Cylonix network
	for your organization.
</p>

<p style="margin: 20px; text-align: center">
	<a href="%s" target="_blank">
		Join Cylonix Network
	</a>
</p>

<p style="margin: 20px; text-align: center; font-size: 80%%">
	Need help getting started? Checkout our documentation at
	<a href="%s" target="_blank">%s</a>,
	or reply to this email to talk to our support team.
</p>

<p>Best regards,</p>
<p>Cylonix Team</p>
<br></br>

<p style="font-size: 80%%">
	Does this email look suspicious or you don't recognize
	the sender? Report abuse by emailing to %s
</p>
`
	InviteShareNodeEmailBody = `
<p>Hello,</p>
<h3 style="margin: 20px; text-align: center">
	A device has been shared with you.
</h3>

<p style="margin: 20px; text-align: center">
	%s has shared a device '%s' with you from their %s Cylonix network.

	Accept the invitation using the button below. Then log in with your
	preferred identity provider and ensure you have Cylonix installed on your
	device. Once you've accepted the invitation, you can connect with %s's
	device over Cylonix.

	You should only accept invites from users you recognize.
</p>

<p style="margin: 20px; text-align: center">
	<a href="%s" target="_blank">
		Accept device invite
	</a>
</p>

<p style="margin: 20px; text-align: center; font-size: 80%%">
	Need help getting started? Checkout our documentation at
	<a href="%s" target="_blank">%s</a>,
	or reply to this email to talk to our support team.
</p>

<p>Best regards,</p>
<p>Cylonix Team</p>
<br></br>

<p style="font-size: 80%%">
	Does this email look suspicious or you don't recognize
	the sender? Report abuse by emailing to %s
</p>
`
)

func inviteEmailSubject(inviterName string, shareNode *string, isInternal bool) string {
	if shareNode != nil {
		return fmt.Sprintf("%s shared a device with you over Cylonix", inviterName)
	}
	if isInternal {
		return fmt.Sprintf("Welcome to join Cylonix network by %s", inviterName)
	}
	return fmt.Sprintf("%s invited you to join Cylonix", inviterName)
}

func inviteEmailBody(inviterName, inviterNetwork, code string, shareNode *string, isInternal bool) string {
	link := utils.InviteURL(code)
	contact, website := utils.GetContactEmailAndCompanyWebsite()
	if shareNode != nil {
		return fmt.Sprintf(
			InviteShareNodeEmailBody, inviterName, *shareNode, inviterNetwork,
			inviterName, link, website, website, contact,
		)
	}
	if isInternal {
		return fmt.Sprintf(
			internalWelcomeEmailBody, inviterName, inviterNetwork, link,
			website, website, contact,
		)
	}
	return fmt.Sprintf(
		externalInviteEmailBody, inviterName, inviterNetwork, link,
		website, website, contact,
	)
}

func inviteLink(code string) string {
	return utils.InviteURL(code)
}