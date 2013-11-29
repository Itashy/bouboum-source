

communites = {
	0:'EN', 1:'FR', 2:'RU',
	3:'BR', 4:'ES', 5:'CN',
	6:'TR', 7:'VK', 8:'PL',
	9:'HU', 10:'NL', 11:'RO',
	12:'ID', 13:'DE', 14:'E2'
}

class opcodes:
	class general:
		protocolVersion = 125
		connectionKey = "xnqbbqufbbu507"
		old_protocol = 4

	class player:
		player = 93

		community = 16

	class system:
		system = 75

		system_info = 32

	class shop:
		shop = 43

		shop_req = 57
		shop_equip = 103

	class lua:
		lua = 13

		lua_exec = 4
