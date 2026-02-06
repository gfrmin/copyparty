"""MIME type mappings and file extension lookups."""

from __future__ import print_function, unicode_literals


MIMES = {
    "opus": "audio/ogg; codecs=opus",
    "owa": "audio/webm; codecs=opus",
}


def _add_mimes() -> None:
    # `mimetypes` is woefully unpopulated on windows
    # but will be used as fallback on linux

    for ln in """text css html csv
application json wasm xml pdf rtf zip jar fits wasm
image webp jpeg png gif bmp jxl jp2 jxs jxr tiff bpg heic heif avif
audio aac ogg wav flac ape amr
video webm mp4 mpeg
font woff woff2 otf ttf
""".splitlines():
        k, vs = ln.split(" ", 1)
        for v in vs.strip().split():
            MIMES[v] = "{}/{}".format(k, v)

    for ln in """text md=plain txt=plain js=javascript
application 7z=x-7z-compressed tar=x-tar bz2=x-bzip2 gz=gzip rar=x-rar-compressed zst=zstd xz=x-xz lz=lzip cpio=x-cpio
application msi=x-ms-installer cab=vnd.ms-cab-compressed rpm=x-rpm crx=x-chrome-extension
application epub=epub+zip mobi=x-mobipocket-ebook lit=x-ms-reader rss=rss+xml atom=atom+xml torrent=x-bittorrent
application p7s=pkcs7-signature dcm=dicom shx=vnd.shx shp=vnd.shp dbf=x-dbf gml=gml+xml gpx=gpx+xml amf=x-amf
application swf=x-shockwave-flash m3u=vnd.apple.mpegurl db3=vnd.sqlite3 sqlite=vnd.sqlite3
text ass=plain ssa=plain
image jpg=jpeg xpm=x-xpixmap psd=vnd.adobe.photoshop jpf=jpx tif=tiff ico=x-icon djvu=vnd.djvu
image heic=heic-sequence heif=heif-sequence hdr=vnd.radiance svg=svg+xml
image arw=x-sony-arw cr2=x-canon-cr2 crw=x-canon-crw dcr=x-kodak-dcr dng=x-adobe-dng erf=x-epson-erf
image k25=x-kodak-k25 kdc=x-kodak-kdc mrw=x-minolta-mrw nef=x-nikon-nef orf=x-olympus-orf
image pef=x-pentax-pef raf=x-fuji-raf raw=x-panasonic-raw sr2=x-sony-sr2 srf=x-sony-srf x3f=x-sigma-x3f
audio caf=x-caf mp3=mpeg m4a=mp4 mid=midi mpc=musepack aif=aiff au=basic qcp=qcelp
video mkv=x-matroska mov=quicktime avi=x-msvideo m4v=x-m4v ts=mp2t
video asf=x-ms-asf flv=x-flv 3gp=3gpp 3g2=3gpp2 rmvb=vnd.rn-realmedia-vbr
font ttc=collection
""".splitlines():
        k, ems = ln.split(" ", 1)
        for em in ems.strip().split():
            ext, mime = em.split("=")
            MIMES[ext] = "{}/{}".format(k, mime)


_add_mimes()


EXTS: dict[str, str] = {v: k for k, v in MIMES.items()}

EXTS["vnd.mozilla.apng"] = "png"

MAGIC_MAP = {"jpeg": "jpg"}
