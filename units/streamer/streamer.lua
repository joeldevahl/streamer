function Unit.Build(self)
	local streamer_src = {
		PathJoin(self.path, "src/streamer.cpp"),
	}

	local streamer_obj = Compile(self.settings, streamer_src)
	local streamer = StaticLibrary(self.settings, "streamer", streamer_obj)
	self:AddProduct(streamer)
end
