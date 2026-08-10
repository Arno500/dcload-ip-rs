# shadowcast-mpv.ps1
# Open a ShadowCast (or any dshow-compatible USB capture device) in mpv
# with low-latency settings.
#
# First run to find the exact device name registered by your driver:
#     .\scripts\shadowcast-mpv.ps1 -ListDevices
#
# Then:
#     .\scripts\shadowcast-mpv.ps1                          # video only
#     .\scripts\shadowcast-mpv.ps1 -WithAudio               # include audio
#     .\scripts\shadowcast-mpv.ps1 -Device "USB Camera"     # override name
#     .\scripts\shadowcast-mpv.ps1 -Size 1280x720           # request resolution
#     .\scripts\shadowcast-mpv.ps1 -Aspect 4/3              # force DAR (default)
#     .\scripts\shadowcast-mpv.ps1 -Aspect 16/9             # letterbox into 16:9 instead
#
# Audio: -WithAudio auto-detects the matching audio device via ffmpeg's
# dshow listing (the video and audio halves of one capture card are usually
# exposed as two separately-named devices, e.g. "ShadowCast" and
# "ShadowCast Audio"). The first audio device whose name contains the
# video device's name wins. Run -ListDevices to see what's available.

param(
    [switch]   $WithAudio = $false,
    [string]   $Device    = "ShadowCast",
    [string]   $Size      = "640x480",
    [int]      $Fps       = 30,
    [string]   $Aspect    = "4/3",
    [switch]   $ListDevices
)

$ErrorActionPreference = "Stop"

# Put PowerShell in UTF-8 mode for native command I/O. By default the
# host decodes native stderr with the legacy code page (e.g. cp1252),
# so a UTF-8 'é' from ffmpeg comes through as the Windows-1252
# misread '─®'. Setting all three is the standard PowerShell idiom
# and is enough on PS 5.1+ for native command output to be decoded
# as UTF-8.
$OutputEncoding          = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8

# Run a native command and capture all output, without letting
# $ErrorActionPreference = "Stop" promote stderr/non-zero exit into
# a terminating error. ffmpeg writes the device list to stderr and
# exits non-zero on a bogus input -- that's expected here.
function Invoke-NativeQuiet {
    param([scriptblock]$Cmd)
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        return & $Cmd 2>&1
    } finally {
        $ErrorActionPreference = $saved
    }
}

if ($ListDevices) {
    if (-not (Get-Command ffmpeg -ErrorAction SilentlyContinue)) {
        throw "ffmpeg is required for -ListDevices (needed to enumerate dshow devices)."
    }
    Invoke-NativeQuiet { ffmpeg -hide_banner -list_devices true -f dshow -i dummy } | ForEach-Object { Write-Host $_ }
    exit 0
}

if (-not (Get-Command mpv -ErrorAction SilentlyContinue)) {
    throw "mpv not found in PATH. Install it via 'scoop install mpv' or 'choco install mpv'."
}

# Walk ffmpeg's dshow device list and pick the audio device whose name
# contains the video device's name as a substring (case-insensitive).
# dshow usually exposes the same capture hardware as two separately-named
# devices, e.g. "ShadowCast" (video) and "ShadowCast Audio" (audio).
function Resolve-AudioDevice {
    param([string]$VideoDevice)

    if (-not (Get-Command ffmpeg -ErrorAction SilentlyContinue)) {
        throw "ffmpeg not found in PATH. Install it (e.g. 'scoop install ffmpeg' or 'choco install ffmpeg')."
    }

    # ffmpeg writes the device list to stderr and exits non-zero (because
    # 'dummy' isn't a valid input); Invoke-NativeQuiet swallows both.
    $output = Invoke-NativeQuiet { ffmpeg -hide_banner -list_devices true -f dshow -i dummy }

    # Each device line looks like:
    #     [dshow @ 0xHASH]   "Device Name" (audio)
    # (Older ffmpeg may also print "DirectShow audio devices" section
    # headers; we don't rely on them.) The "Alternative name" lines have
    # a different shape and are skipped automatically because they don't
    # carry the " (audio)" suffix.
    $audioDevices = @()
    foreach ($line in $output) {
        $s = [string]$line
        # Unanchored match on purpose: PowerShell can prefix captured
        # native-stderr lines with "<exe> : ", and a device name may
        # legitimately contain spaces. Only the " (audio)" suffix is
        # a reliable signal.
        if ($s -match '\[dshow @\s+\S+\]\s+"(?<n>[^"]+)"\s+\(audio\)') {
            $audioDevices += $matches['n']
        }
    }

    $hit = $audioDevices | Where-Object { $_ -like "*$VideoDevice*" } | Select-Object -First 1
    if (-not $hit) {
        $avail = if ($audioDevices.Count) { $audioDevices -join ', ' } else { '<none>' }
        throw "No audio device matched '$VideoDevice'. Audio devices seen by ffmpeg: $avail. Run with -ListDevices for the full picture."
    }
    return $hit
}

# dshow URL must be a single argument to mpv. Spaces in the device name are
# URL-encoded because dshow:// parses the URL itself.
$encoded = [uri]::EscapeDataString($Device)
$url     = "av://dshow:video=$encoded"
if ($WithAudio) {
    $audioName  = Resolve-AudioDevice -VideoDevice $Device
    $url       += ":audio=`"$audioName`""
    Write-Host "Audio device: $audioName"
}

# Build the per-stream options (video_size / framerate) the dshow demuxer
# accepts in the URL query string.
$query = ""
if ($Size) { $query += "video_size=$Size" }
if ($Fps  -gt 0) {
    if ($query) { $query += "," }
    $query += "framerate=$Fps,pixel_format=yuyv422"
}
if ($WithAudio) {
    if ($query) { $query += "," }
    $query += "audio_buffer_size=4"
}

# Low-latency flag set:
#   --cache=no / --demuxer-lavf-o=fflags=+nobuffer+flush_packets  no buffering
#   --video-sync=display-vdrop                                   snap to display, drop on mismatch
#   --framedrop=no --interpolation=no                             no smoothing
#   --keep-open=no                                                quit if stream dies
#   --hwdec=auto-safe                                             GPU decode if possible
#   --terminal=no                                                 no OSD spam
#   --video-aspect-override=<ratio>                              override display aspect (e.g. 4/3)
$mpvArgs = @(
    "--no-cache"
    "--profile=low-latency"
    "--demuxer-lavf-o-add=fflags=+nobuffer"
	"--demuxer-readahead-secs=0"
	"--video-sync=display-resample"
	"--framedrop=no"
	"--autosync=1000"
	"--video-sync-max-video-change=50"
	"--video-sync-max-audio-change=1"
	"--initial-audio-sync=no"
    "--keep-open=no"
    "--force-window=yes"
    "--title=ShadowCast"
	"--ontop"
    "--video-aspect-override=$Aspect"
    "--demuxer-lavf-o=$query"
    "--cache=no"
    $url
)

if ($WithAudio) {
    $mpvArgs = @("--volume-gain=12"
        "--initial-audio-sync=no") + $mpvArgs
} else {
    $mpvArgs = @("--no-audio") + $mpvArgs
}

Write-Host "Opening $Device via dshow..."
mpv @mpvArgs
