# coding: utf-8
"""Authentication context and middleware for HTTP requests."""
from __future__ import print_function, unicode_literals


def resolve_credentials(headers, uparam, cookie_pw, args, asrv):
    """Extract password and resolve username from request.

    Pure function: no side effects, no self references.

    Returns (password, username).
    """
    from .util import b64dec

    zso = headers.get("authorization")
    bauth = ""
    if (
        zso
        and not args.no_bauth
        and (not cookie_pw or not args.bauth_last)
    ):
        try:
            zb = zso.split(" ")[1].encode("ascii")
            zs = b64dec(zb).decode("utf-8")
            # try "pwd", "x:pwd", "pwd:x"
            for bauth in [zs] + zs.split(":", 1)[::-1]:
                if bauth in asrv.sesa:
                    break
                hpw = asrv.ah.hash(bauth)
                if asrv.iacct.get(hpw):
                    break
        except (ValueError, TypeError, UnicodeDecodeError, IndexError):
            pass

    pw = (
        uparam.get(args.pw_urlp)
        or headers.get(args.pw_hdr)
        or bauth
        or cookie_pw
    )
    uname = (
        asrv.sesa.get(pw)
        or asrv.iacct.get(asrv.ah.hash(pw))
        or "*"
    )
    return pw, uname


def resolve_ip_user(uname, ip, args, conn, log):
    """Apply --ipu and --ipr overrides. Returns final username.

    Pure function aside from logging.
    """
    if args.have_ipu_or_ipr:
        if args.ipu and (uname == "*" or args.ao_ipu_wins):
            uname = conn.ipu_iu[conn.ipu_nm.map(ip)]
        ipr = conn.hsrv.ipr
        if ipr and uname in ipr:
            if not ipr[uname].map(ip):
                log("username [%s] rejected by --ipr" % (uname,), 3)
                uname = "*"
    return uname


def resolve_permissions(uname, vpath, asrv):
    """Resolve VFS node and per-node permissions for a user.

    Returns (vn, avn, rem, perms_tuple) where perms_tuple is:
        (can_read, can_write, can_move, can_delete,
         can_get, can_upget, can_html, can_admin, can_dot)
    """
    vn, rem = asrv.vfs.get(vpath, uname, False, False)
    if vn.realpath and ("xdev" in vn.flags or "xvol" in vn.flags):
        ap = vn.canonical(rem)
        avn = vn.chk_ap(ap)
    else:
        avn = vn

    can_read = False
    can_write = False
    can_move = False
    can_delete = False
    can_get = False
    can_upget = False
    can_html = False
    can_admin = False
    can_dot = False

    try:
        assert avn  # type: ignore  # !rm
        (
            can_read,
            can_write,
            can_move,
            can_delete,
            can_get,
            can_upget,
            can_html,
            can_admin,
            can_dot,
        ) = avn.uaxs[uname]
    except:
        pass  # default is all-false

    return vn, avn, rem, (
        can_read, can_write, can_move, can_delete,
        can_get, can_upget, can_html, can_admin, can_dot,
    )
