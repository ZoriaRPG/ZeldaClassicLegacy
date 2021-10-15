#ifndef ZC_GUI_DIALOGMESSAGE_H
#define ZC_GUI_DIALOGMESSAGE_H

#include <functional>
#include <string_view>
#include <utility>
#include <variant>

namespace GUI
{

class MessageArg
{
public:
	/* Use this when a message has no argument. */
	static constexpr auto none = std::monostate();

	inline constexpr MessageArg() noexcept: value(std::monostate())
	{}

	inline constexpr MessageArg(const MessageArg& other) noexcept=default;

	inline constexpr MessageArg(MessageArg&& other) noexcept=default;

	// You would think a template constructor would work, but apparently not.
	inline constexpr MessageArg(std::monostate) noexcept: value(none)
	{}

	inline constexpr MessageArg(bool value) noexcept: value(value)
	{}

	inline constexpr MessageArg(int value) noexcept: value(value)
	{}

	inline constexpr MessageArg(std::string_view value) noexcept: value(value)
	{}

	/* Returns true if the argument is the specified type. */
	template<typename T>
	inline constexpr bool is() const
	{
		return std::holds_alternative<T>(value);
	}

	inline constexpr operator bool() const
	{
		return std::get<bool>(value);
	}

	inline constexpr operator int() const
	{
		return std::get<int>(value);
	}

	inline constexpr operator std::string_view() const
	{
		return std::get<std::string_view>(value);
	}

private:
	std::variant<
		std::monostate,
		bool,
		int,
		std::string_view
	> value;
};

using MessageDispatcher = std::function<void(int, MessageArg)>;

}

#endif
