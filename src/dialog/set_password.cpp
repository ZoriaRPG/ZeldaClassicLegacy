#include "set_password.h"
#include <gui/builder.h>

SetPasswordDialog::SetPasswordDialog(bool useKeyFile,
	std::function<void(std::string_view, bool)> setPassword):
		useKeyFile(useKeyFile), setPassword(setPassword)
{}

std::shared_ptr<GUI::Widget> SetPasswordDialog::view()
{
	using namespace GUI::Builder;
	using namespace GUI::Props;

	return Window(
		title = "Set Password",
		onEnter = message::OK,
		onClose = message::CANCEL,
		Column(
			Rows<2>(
				Label(text = "Enter new password:"),
				this->pwField = TextField(
					maxLength = 255,
					focused = true),
				this->saveKeyFileCB = Checkbox(
					text = "&Save key file",
					checked = this->useKeyFile)
			),
			Row(
				topMargin = 0.5_em,
				vAlign = 1.0,
				spacing = 2_em,
				Button(
					text = "OK",
					onClick = message::OK),
				Button(
					text = "Cancel",
					onClick = message::CANCEL)
			)
		)
	);
}

bool SetPasswordDialog::handleMessage(message msg)
{
	switch(msg)
	{
	case message::OK:
		setPassword(pwField->getText(), saveKeyFileCB->getChecked());
		[[fallthrough]];
	case message::CANCEL:
	default:
		return true;
	}
}
