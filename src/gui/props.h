#ifndef ZCGUI_PROPS_H
#define ZCGUI_PROPS_H

namespace GUI::Props
{

struct Property {};

// gcc -Weffc++ will complain "'operator=' should return a reference to '*this'"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"
#endif

ZCGUI_DECLARE_PROPERTY(bottomMargin)
ZCGUI_DECLARE_PROPERTY(boxPlacement)
ZCGUI_DECLARE_PROPERTY(checked)
ZCGUI_DECLARE_PROPERTY(columnSpacing)
ZCGUI_DECLARE_PROPERTY(data)
ZCGUI_DECLARE_PROPERTY(focused)
ZCGUI_DECLARE_PROPERTY(hAlign)
ZCGUI_DECLARE_PROPERTY(height)
ZCGUI_DECLARE_PROPERTY(hMargins)
ZCGUI_DECLARE_PROPERTY(leftMargin)
ZCGUI_DECLARE_PROPERTY(margins)
ZCGUI_DECLARE_PROPERTY(maxLength)
ZCGUI_DECLARE_PROPERTY(maxLines)
ZCGUI_DECLARE_PROPERTY(onClick)
ZCGUI_DECLARE_PROPERTY(onClose)
ZCGUI_DECLARE_PROPERTY(onSelectionChanged)
ZCGUI_DECLARE_PROPERTY(onValueChanged)
ZCGUI_DECLARE_PROPERTY(onEnter)
ZCGUI_DECLARE_PROPERTY(rightMargin)
ZCGUI_DECLARE_PROPERTY(rowSpacing)
ZCGUI_DECLARE_PROPERTY(selectedValue)
ZCGUI_DECLARE_PROPERTY_AS(shortcuts, std::initializer_list<KeyboardShortcut>)
ZCGUI_DECLARE_PROPERTY(spacing)
ZCGUI_DECLARE_PROPERTY(text)
ZCGUI_DECLARE_PROPERTY(title)
ZCGUI_DECLARE_PROPERTY(topMargin)
ZCGUI_DECLARE_PROPERTY(type)
ZCGUI_DECLARE_PROPERTY(vAlign)
ZCGUI_DECLARE_PROPERTY(visible)
ZCGUI_DECLARE_PROPERTY(vMargins)
ZCGUI_DECLARE_PROPERTY(width)

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

} // namespace GUI::Props

namespace GUI::Internal
{

// Clang will complain that definitions of tag types aren't available.
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundefined-var-template"
#endif

template<typename ArgsSoFar, typename BuilderType>
inline void applyArgs(ArgsSoFar, BuilderType&&)
{
}

template<typename ArgsSoFar, typename BuilderType, typename WidgetType,
    typename... MoreArgsType>
inline void applyArgs(ArgsSoFar, BuilderType&& builder, std::shared_ptr<WidgetType> child,
    MoreArgsType&&... moreArgs)
{
    builder.addChildren(child, std::forward<MoreArgsType>(moreArgs)...);
}

template<typename PropsSoFar, typename BuilderType, typename WidgetType>
inline void applyArgs(PropsSoFar, BuilderType&& builder, std::shared_ptr<WidgetType> child)
{
    builder.addChildren(child);
}

template<typename PropsSoFar, typename BuilderType, typename PropType>
inline void applyArgs(PropsSoFar psf, BuilderType&& builder, PropType&& prop)
{
    using DecayType = typename std::decay_t<PropType>;
    ZCGUI_STATIC_ASSERT((std::is_base_of_v<Props::Property, DecayType>),
        "Arguments must be widget properties or widgets.");
    prop.assertUnique(psf);

    builder.applyProp(std::forward<PropType>(prop), PropType::tag);
}

template<typename PropsSoFar, typename BuilderType, typename PropType, typename... MoreArgsType>
inline void applyArgs(PropsSoFar psf, BuilderType&& builder, PropType&& prop,
    MoreArgsType&&... moreArgs)
{
    using DecayType = typename std::decay_t<PropType>;
    ZCGUI_STATIC_ASSERT((std::is_base_of_v<Props::Property, DecayType>),
        "Arguments must be widget properties or widgets." ZCGUI_NEWLINE
        "This may be a name collision." ZCGUI_NEWLINE
        "Is there something else with the same name in scope?");
    prop.assertUnique(psf);

    builder.applyProp(std::forward<PropType>(prop), PropType::tag);

    class PropsApplied: DecayType::TagType {};
    applyArgs(PropsApplied(), std::forward<BuilderType>(builder),
        std::forward<MoreArgsType>(moreArgs)...);
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif

} // namespace GUI::Internal

#endif
