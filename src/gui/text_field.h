#ifndef ZC_GUI_TEXTFIELD_H
#define ZC_GUI_TEXTFIELD_H

#include "widget.h"
#include "dialog_ref.h"
#include <memory>
#include <string_view>

namespace GUI
{

class TextField: public Widget
{
public:
	enum class type
	{
		TEXT, INT_DECIMAL, INT_HEX
	};

	TextField();

	/* Set the text field's input type. This determines how the text
	 * will be interpreted when a message is sent.
	 */
	inline void setType(type newType)
	{
		tfType = newType;
	}

	/* Set the current text. If it's longer than the current maximum length,
	 * only that many characters will be kept. However, if the maximum length
	 * is 0, the maximum length will be set to the length of the text.
	 */
	void setText(std::string_view newText);

	/* Returns the current text. This does not interpret the text according to
	 * the type. The string_view will include a null terminator. It's owned by
	 * the TextField, so don't hold on to it after the dialog is closed.
	 */
	std::string_view getText();

	/* Set the maximum length of the text, not including the null terminator.
	 */
	void setMaxLength(size_t newMax);

	/* Sets the message to send when the enter key is pressed. Note that
	 * the type of the argument varies depending on the text field's type.
	 * If set to Text, the argument will be a std::string_view. If set to
	 * IntDecimal or IntHex, it will be an int.
	 */
	template<typename T>
	RequireMessage<T> onEnter(T m)
	{
		onEnterMsg = static_cast<int>(m);
	}

	/* Sets the message to send whenever the text changes. Like onEnter,
	 * the type of the argument varies depending on the text field's type.
	 */
	template<typename T>
	RequireMessage<T> onValueChanged(T m)
	{
		onValueChangedMsg = static_cast<int>(m);
	}

private:
	std::unique_ptr<char[]> buffer;
	type tfType;
	size_t maxLength;
	DialogRef alDialog;
	int onEnterMsg, onValueChangedMsg;

	void applyVisibility(bool visible) override;
	void realize(DialogRunner& runner) override;
	int onEvent(int event, MessageDispatcher& sendMessage) override;
};

}

#endif
