#pragma once
#include "../ptm_ctx/ptm_ctx.hpp"

namespace nasa
{
	class injector_ctx
	{
	public:
		explicit injector_ctx(ptm::ptm_ctx* map_into, ptm::ptm_ctx* map_from);
		~injector_ctx();

		auto translate(std::uintptr_t) const -> std::uintptr_t;
		auto init() const -> bool;
	private:
		// std::uint8_t is 2^8 = 256 which is the same amount
		// of possible usermode pml4e's...
		//
		// also this is "real pml4e index" ---> "inserted pml4e index"
		mutable std::map<std::uint8_t, std::uint8_t> pml4_index_map;
		ptm::ptm_ctx* map_into, *map_from;
	};
}