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
	%s has invited you to join Cylonix. You can use Cylonix to securely share
	devices and services.
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
	<a href="https://cylonix.io" target="_blank">Cylonix.io</a>,
	or reply to this email to talk to our support team.
</p>

<p>Best regards,</p>
<p>Cylonix Team</p>
<br></br>

<p style="font-size: 80%%">
	Does this email look suspicious or you don't recognize
	the sender? Report abuse by emailing to contact@cylonix.io
</p>
`

	internalWelcomeEmailBody = `
<p>Hello,</p>
<h3 style="margin: 20px; text-align: center">
	Welcome to join the Cylonix network.
</h3>

<p style="margin: 20px; text-align: center">
	%s has invited you to join Cylonix. You can use Cylonix to securely share
	devices and services.
</p>

<p style="margin: 20px; text-align: center">
	Please click the link below to accept the invitation.
	Then sign in with your oranization's sign-in provider,
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
	<a href="https://cylonix.io" target="_blank">Cylonix.io</a>,
	or reply to this email to talk to our support team.
</p>

<p>Best regards,</p>
<p>Cylonix Team</p>
<br></br>

<p style="font-size: 80%%">
	Does this email look suspicious or you don't recognize
	the sender? Report abuse by emailing to contact@cylonix.io
</p>
`
)

func inviteEmailSubject(inviterName string, isInternal bool) string {
	if isInternal {
		return fmt.Sprintf("Welcome to join Cylonix network by %s", inviterName)
	}
	return fmt.Sprintf("%s invited you to join Cylonix", inviterName)
}

func inviteEmailBody(inviterName, code string, isInternal bool) string {
	link := utils.InviteURL(code)
	if isInternal {
		return fmt.Sprintf(internalWelcomeEmailBody, inviterName, link)
	}
	return fmt.Sprintf(externalInviteEmailBody, inviterName, link)
}

func inviteLink(code string) string {
	return utils.InviteURL(code)
}