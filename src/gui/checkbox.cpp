#include "checkbox.h"
#include "common.h"
#include "dialog.h"
#include "dialog_runner.h"
#include "../jwin.h"
#include "../zquest.h"
#include <cassert>
#include <utility>

#define FONT sized(nfont, lfont_l)

namespace GUI
{

Checkbox::Checkbox(): checked(false), text(),
	placement(boxPlacement::LEFT), alDialog(), message(-1)
{
	setPreferredHeight(Size::pixels(text_height(FONT))+2_lpx);
	setPreferredWidth(Size::largePixels(13));
}

void Checkbox::setText(std::string newText)
{
	int textWidth = text_length(FONT, newText.c_str());
	setPreferredWidth(Size::pixels(textWidth)+13_lpx);
	text = std::move(newText);
}

void Checkbox::setChecked(bool value)
{
	checked = value;
	if(alDialog)
	{
		if(checked)
			alDialog->flags |= D_SELECTED;
		else
			alDialog->flags &= ~D_SELECTED;
	}
}

bool Checkbox::getChecked()
{
	return alDialog ? alDialog->flags&D_SELECTED : checked;
}

void Checkbox::applyVisibility(bool visible)
{
	if(alDialog)
	{
		if(visible)
			alDialog->flags &= ~D_HIDDEN;
		else
			alDialog->flags |= D_HIDDEN;
	}
}

void Checkbox::realize(DialogRunner& runner)
{
	alDialog = runner.push(shared_from_this(), DIALOG {
		jwin_checkfont_proc,
		x, y, getWidth(), getHeight(),
		fgColor, bgColor,
		getAccelKey(text),
		getFlags()|(checked ? D_SELECTED : 0),
		static_cast<int>(placement), 0, // d1, d2,
		text.data(), FONT, nullptr // dp, dp2, dp3
	});
}

int Checkbox::onEvent(int event, MessageDispatcher& sendMessage)
{
	assert(event == geTOGGLE);
	if(message >= 0)
		sendMessage(message, (alDialog->flags&D_SELECTED) != 0);
	return -1;
}

}
