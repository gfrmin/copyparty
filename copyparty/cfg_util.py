"""Configuration utility functions for copyparty.

Pure functions for config file parsing, format upgrade, and argument derivation.
No dependency on AuthSrv class.
"""

import argparse
import os
import sys
from typing import Any, Optional

from .__init__ import TYPE_CHECKING
from .util import absreal, read_utf8

if TYPE_CHECKING:
    from .util import NamedLogger


def derive_args(args: argparse.Namespace) -> None:
    args.have_idp_hdrs = bool(args.idp_h_usr or args.idp_hm_usr)
    args.have_ipu_or_ipr = bool(args.ipu or args.ipr)


def n_du_who(s: str) -> int:
    if s == "all":
        return 9
    if s == "auth":
        return 7
    if s == "w":
        return 5
    if s == "rw":
        return 4
    if s == "a":
        return 3
    return 0


def n_ver_who(s: str) -> int:
    if s == "all":
        return 9
    if s == "auth":
        return 6
    if s == "a":
        return 3
    return 0


def split_cfg_ln(ln: str) -> dict[str, Any]:
    # "a, b, c: 3" => {a:true, b:true, c:3}
    ret = {}
    while True:
        ln = ln.strip()
        if not ln:
            break
        ofs_sep = ln.find(",") + 1
        ofs_var = ln.find(":") + 1
        if not ofs_sep and not ofs_var:
            ret[ln] = True
            break
        if ofs_sep and (ofs_sep < ofs_var or not ofs_var):
            k, ln = ln.split(",", 1)
            ret[k.strip()] = True
        else:
            k, ln = ln.split(":", 1)
            ret[k.strip()] = ln.strip()
            break
    return ret


def expand_config_file(
    log: Optional["NamedLogger"], ret: list[str], fp: str, ipath: str
) -> None:
    """expand all % file includes"""
    fp = absreal(fp)
    if len(ipath.split(" -> ")) > 64:
        raise Exception("hit max depth of 64 includes")

    if os.path.isdir(fp):
        names = list(sorted(os.listdir(fp)))
        cnames = [
            x for x in names if x.lower().endswith(".conf") and not x.startswith(".")
        ]
        if not cnames:
            t = "warning: tried to read config-files from folder '%s' but it does not contain any "
            if names:
                t += ".conf files; the following files/subfolders were ignored: %s"
                t = t % (fp, ", ".join(names[:8]))
            else:
                t += "files at all"
                t = t % (fp,)

            if log:
                log(t, 3)

            ret.append("#\033[33m %s\033[0m" % (t,))
        else:
            zs = "#\033[36m cfg files in %s => %s\033[0m" % (fp, cnames)
            ret.append(zs)

        for fn in cnames:
            fp2 = os.path.join(fp, fn)
            if fp2 in ipath:
                continue

            expand_config_file(log, ret, fp2, ipath)

        return

    if not os.path.exists(fp):
        t = "warning: tried to read config from '%s' but the file/folder does not exist"
        t = t % (fp,)
        if log:
            log(t, 3)

        ret.append("#\033[31m %s\033[0m" % (t,))
        return

    ipath += " -> " + fp
    ret.append("#\033[36m opening cfg file{}\033[0m".format(ipath))

    cfg_lines = read_utf8(log, fp, True).replace("\t", " ").split("\n")
    if True:  # diff-golf
        for oln in [x.rstrip() for x in cfg_lines]:
            ln = oln.split("  #")[0].strip()
            if ln.startswith("% "):
                pad = " " * len(oln.split("%")[0])
                fp2 = ln[1:].strip()
                fp2 = os.path.join(os.path.dirname(fp), fp2)
                ofs = len(ret)
                expand_config_file(log, ret, fp2, ipath)
                for n in range(ofs, len(ret)):
                    ret[n] = pad + ret[n]
                continue

            ret.append(oln)

    ret.append("#\033[36m closed{}\033[0m".format(ipath))

    zsl = []
    for ln in ret:
        zs = ln.split("  #")[0]
        if " #" in zs and zs.split("#")[0].strip():
            zsl.append(ln)
    if zsl and "no-cfg-cmt-warn" not in "\n".join(ret):
        t = "\033[33mWARNING: there is less than two spaces before the # in the following config lines, so instead of assuming that this is a comment, the whole line will become part of the config value:\n\n>>> %s\n\nif you are familiar with this and would like to mute this warning, specify the global-option no-cfg-cmt-warn\n\033[0m"
        t = t % ("\n>>> ".join(zsl),)
        if log:
            log(t)
        else:
            print(t, file=sys.stderr)


def upgrade_cfg_fmt(
    log: Optional["NamedLogger"], args: argparse.Namespace, orig: list[str], cfg_fp: str
) -> list[str]:
    """convert from v1 to v2 format"""
    zst = [x.split("#")[0].strip() for x in orig]
    zst = [x for x in zst if x]
    if (
        "[global]" in zst
        or "[accounts]" in zst
        or "accs:" in zst
        or "flags:" in zst
        or [x for x in zst if x.startswith("[/")]
        or len(zst) == len([x for x in zst if x.startswith("%")])
    ):
        return orig

    zst = [x for x in orig if "#\033[36m opening cfg file" not in x]
    incl = len(zst) != len(orig) - 1

    t = "upgrading config file [{}] from v1 to v2"
    if not args.vc:
        t += ". Run with argument '--vc' to see the converted config if you want to upgrade"
    if incl:
        t += ". Please don't include v1 configs from v2 files or vice versa! Upgrade all of them at the same time."
    if log:
        log(t.format(cfg_fp), 3)

    ret = []
    vp = ""
    ap = ""
    cat = ""
    catg = "[global]"
    cata = "[accounts]"
    catx = "  accs:"
    catf = "  flags:"
    for ln in orig:
        sn = ln.strip()
        if not sn:
            cat = vp = ap = ""
        if not sn.split("#")[0]:
            ret.append(ln)
        elif sn.startswith("-") and cat in ("", catg):
            if cat != catg:
                cat = catg
                ret.append(cat)
            sn = sn.lstrip("-")
            zst = sn.split(" ", 1)
            if len(zst) > 1:
                sn = "{}: {}".format(zst[0], zst[1].strip())
            ret.append("  " + sn)
        elif sn.startswith("u ") and cat in ("", catg, cata):
            if cat != cata:
                cat = cata
                ret.append(cat)
            s1, s2 = sn[1:].split(":", 1)
            ret.append("  {}: {}".format(s1.strip(), s2.strip()))
        elif not ap:
            ap = sn
        elif not vp:
            vp = "/" + sn.strip("/")
            cat = "[{}]".format(vp)
            ret.append(cat)
            ret.append("  " + ap)
        elif sn.startswith("c "):
            if cat != catf:
                cat = catf
                ret.append(cat)
            sn = sn[1:].strip()
            if "=" in sn:
                zst = sn.split("=", 1)
                sn = zst[0].replace(",", ", ")
                sn += ": " + zst[1]
            else:
                sn = sn.replace(",", ", ")
            ret.append("    " + sn)
        elif sn[:1] in "rwmdgGhaA.":
            if cat != catx:
                cat = catx
                ret.append(cat)
            zst = sn.split(" ")
            zst = [x for x in zst if x]
            if len(zst) == 1:
                zst.append("*")
            ret.append("    {}: {}".format(zst[0], ", ".join(zst[1:])))
        else:
            t = "did not understand line {} in the config"
            t1 = t
            n = 0
            for ln in orig:
                n += 1
                t += "\n{:4} {}".format(n, ln)
            if log:
                log(t, 1)
            else:
                print("\033[31m" + t)
            raise Exception(t1)

    if args.vc and log:
        t = "new config syntax (copy/paste this to upgrade your config):\n"
        t += "\n# ======================[ begin upgraded config ]======================\n\n"
        for ln in ret:
            t += ln + "\n"
        t += "\n# ======================[ end of upgraded config ]======================\n"
        log(t)

    return ret
