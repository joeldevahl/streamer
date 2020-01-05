Unit:Using("streamer")

Unit:Using("jc_test")

function Unit.Init(self)
	self.executable = true
	self.targetname = "test"
end

function Unit.Build(self)
	if target.family == "windows" then
		self.settings.dll.libs:Add("user32")
	end

	local common_src = Collect(self.path .. "/src/*.cpp")
	local common_obj = Compile(self.settings, common_src)

	local bin = Link(self.settings, self.targetname, common_obj)
	self:AddProduct(bin)
end
