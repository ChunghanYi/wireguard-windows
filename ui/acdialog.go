/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 Slowboot(chunghan.yi@gmail.com) LLC. All Rights Reserved.
 */

package ui

import (
	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/manager"

	"golang.zx2c4.com/wireguard/windows/l18n"
)

var (
	showingACDialog *walk.Dialog
	serveripEdit *walk.LineEdit
	portEdit     *walk.LineEdit
)

func onAutoConnect(owner walk.Form) {
	showError(runACDialog(owner), owner)
}

func runACDialog(owner walk.Form) error {
	if showingACDialog != nil {
		showingACDialog.Show()
		raise(showingACDialog.Handle())
		return nil
	}

	vbl := walk.NewVBoxLayout()
	vbl.SetMargins(walk.Margins{80, 20, 80, 20})
	vbl.SetSpacing(10)

	var disposables walk.Disposables
	defer disposables.Treat()

	var err error
	showingACDialog, err = walk.NewDialogWithFixedSize(owner)
	if err != nil {
		return err
	}
	defer func() {
		showingACDialog = nil
	}()
	disposables.Add(showingACDialog)

	showingACDialog.SetTitle(l18n.Sprintf("WireGuard Auto Connect"))

	showingACDialog.SetLayout(vbl)
	if icon, err := loadLogoIcon(32); err == nil {
		showingACDialog.SetIcon(icon)
	}

	font, _ := walk.NewFont("Segoe UI", 9, 0)
	showingACDialog.SetFont(font)

	var serverIp, serverPort string
	if !manager.GetACServerInfo(&serverIp, &serverPort) {
		serverIp = "192.168.8.235"
		serverPort = "51822"
	}

	serveripLabel, err := walk.NewTextLabel(showingACDialog)
	if err != nil {
		return err
	}
	serveripLabel.SetText(l18n.Sprintf("&ServerIP:"))

	if serveripEdit, err = walk.NewLineEdit(showingACDialog); err != nil {
		return err
	}

	serveripEdit.SetText(serverIp)

	portLabel, err := walk.NewTextLabel(showingACDialog)
	if err != nil {
		return err
	}
	portLabel.SetText(l18n.Sprintf("&Port:"))
	if portEdit, err = walk.NewLineEdit(showingACDialog); err != nil {
		return err
	}
	portEdit.SetText(serverPort)

	buttonCP, err := walk.NewComposite(showingACDialog)
	if err != nil {
		return err
	}
	hbl := walk.NewHBoxLayout()
	hbl.SetMargins(walk.Margins{VNear: 10})
	buttonCP.SetLayout(hbl)
	walk.NewHSpacer(buttonCP)
	closePB, err := walk.NewPushButton(buttonCP)
	if err != nil {
		return err
	}
	closePB.SetAlignment(walk.AlignHCenterVNear)
	closePB.SetText(l18n.Sprintf(" Start Auto Connect "))
	closePB.Clicked().Attach(func() {
		var acserver manager.ACServerInfo
		acserver.ServerIp = serveripEdit.Text()
		acserver.ServerPort = portEdit.Text()

		manager.IPCClientAutoConnect(&acserver)
		showingACDialog.Accept()
	})

	walk.NewHSpacer(buttonCP)

	showingACDialog.SetCancelButton(closePB)

	disposables.Spare()

	showingACDialog.Run()

	return nil
}
