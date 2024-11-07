function Analyze(info)
  info.Extra = info.Extra or {}
  info.Extra.snapshot = "/axis-cgi/mjpg/video.cgi?camera=&resolution=640x480"

  return info
end
