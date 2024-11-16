 
function Analyze(info)
  info.Extra = info.Extra or {}
  info.Extra.snapshot =  "/mjpg/video.mjpg"
 
  info.Extra.adminpage = "/view/viewer_index.shtml"

  return info
    
end
 