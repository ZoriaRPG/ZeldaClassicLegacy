#include "common.h"
#include "../zq_misc.h"
#include "../zquest.h"
#include <boost/format.hpp>
#include <algorithm>
#include <array>
#include <vector>

GUI::ListData getItemListData(bool includeNone)
{
	std::vector<GUI::ListItem> listItems;
	listItems.reserve(ITEMCNT+(includeNone ? 1 : 0));

	if(includeNone)
		listItems.emplace_back("(None)", -1);
	for(int i = 0; i < ITEMCNT; ++i)
		listItems.emplace_back(item_string[i], i);

	auto sortBegin = listItems.begin();
	if(includeNone)
		++sortBegin;
	std::sort(sortBegin, listItems.end(),
		[](const auto& a, const auto& b)
		{
			return a.text<b.text;
		});

	return GUI::ListData(std::move(listItems));
}

GUI::ListData getStringListData()
{
	std::vector<size_t> msgMap(msg_count, 0);
	for(size_t i = 0; i < msg_count; ++i)
	{
		auto& msg = MsgStrings[i];
		msgMap[msg.listpos] = i;
	}

	return GUI::ListData(msg_count,
		[&msgMap](size_t index)
		{
			return boost::str(boost::format("%1%: %2%")
				% msgMap[index]
				% MsgStrings[msgMap[index]].s);
		},
		[&msgMap](size_t index)
		{
			return msgMap[index];
		});
}

GUI::ListData getShopListData()
{
	return GUI::ListData(256,
		[](size_t index)
		{
			return boost::str(boost::format("%1%:  %2%")
				% index
				% misc.shop[index].name);
		},
		[](size_t index)
		{
			return index;
		});
}

GUI::ListData getInfoShopListData()
{
	return GUI::ListData(256,
		[](size_t index)
		{
			return boost::str(boost::format("%1%:  %2%")
				% index
				% misc.info[index].name);
		},
		[](size_t index)
		{
			return index;
		});
}
