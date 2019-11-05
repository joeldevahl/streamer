local ep = string.gsub(ModuleFilename(), "bam.lua", "")
Import(PathJoin(ep, "build/engine.lua"))

engine.project_name = "streamer"

AddConfig("debug", "configs/debug.lua")
AddConfig("release", "configs/release.lua")

if engine.host.family == "windows" then
	AddTarget("winx64", "targets/winx64.lua")
elseif engine.host.platform == "macosx" then
	AddTarget("osx_x86_64", "targets/osx_x86_64.lua")
end

AddStep("init", "steps/init.lua")
AddStep("addtools", "steps/addtools.lua")
AddStep("patch", "steps/patch.lua")
AddStep("build", "steps/build.lua")
AddStep("projgen", "steps/projgen.lua")

Init()

AddUnitsInDir("externals")
AddUnitsInDir("units")
AddUnitsInDir("projects")

Build()
