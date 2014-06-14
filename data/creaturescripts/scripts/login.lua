function onLogin(cid)
	local player = Player(cid)

	player:registerEvent("PlayerDeath")
	return true
end