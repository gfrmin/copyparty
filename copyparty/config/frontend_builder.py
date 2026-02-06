"""Frontend configuration builder for copyparty.

Builds JavaScript configuration dictionaries for frontend rendering.
"""

from typing import Any, Dict, Optional


class FrontendConfigBuilder:
    """Build frontend configuration for browser and UI."""

    def __init__(self, log_func: Any = None):
        """Initialize builder with optional logging function.

        Args:
            log_func: Optional logging function
        """
        self.log = log_func

    def build_volume_listing_config(self, vn: Any, vf: Dict[str, Any]) -> Dict[str, Any]:
        """Build JavaScript listing configuration for a volume.

        Args:
            vn: Volume node
            vf: Volume flags

        Returns:
            Dictionary of listing configuration options
        """
        config = {
            "idx": "e2d" in vf,
            "itag": "e2t" in vf,
            "dlni": "dlni" in vf,
            "dgrid": "grid" in vf,
            "sort": vf.get("sort", "n"),
            "hsortn": vf.get("hsortn", ""),
            "crop": vf.get("crop", ""),
            "th3x": vf.get("th3x", ""),
            "u2ts": vf.get("u2ts", ""),
            "shr_who": vf.get("shr_who", ""),
            "frand": bool(vf.get("rand", False)),
            "lifetime": vf.get("lifetime", 0),
            "unlist": vf.get("unlist", ""),
            "sb_lg": "" if "no_sb_lg" in vf else (vf.get("lg_sbf") or "y"),
            "sb_md": "" if "no_sb_md" in vf else (vf.get("md_sbf") or "y"),
        }

        if "ufavico_h" in vf:
            config["ufavico"] = vf["ufavico_h"]

        return config

    def build_volume_html_config(
        self,
        vn: Any,
        vf: Dict[str, Any],
        args: Any,
        listing_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build JavaScript HTML/UI configuration for a volume.

        Args:
            vn: Volume node
            vf: Volume flags
            args: Command-line arguments
            listing_config: Previously built listing config

        Returns:
            Dictionary of HTML/UI configuration options
        """
        config = {
            "SPINNER": getattr(args, "spinner", "entropy"),
            "s_name": getattr(args, "bname", "copyparty"),
            "idp_login": getattr(args, "idp_login", ""),
            "have_up2k_idx": "e2d" in vf,
            "have_acode": not getattr(args, "no_acode", False),
            "have_c2flac": getattr(args, "allow_flac", False),
            "have_c2wav": getattr(args, "allow_wav", False),
            "have_shr": bool(getattr(args, "shr", "")),
            "shr_who": vf.get("shr_who", ""),
            "have_zip": not getattr(args, "no_zip", False),
            "have_zls": not getattr(args, "no_zls", False),
            "have_mv": not getattr(args, "no_mv", False),
            "have_del": not getattr(args, "no_del", False),
            "have_unpost": int(getattr(args, "unpost", 0)),
            "have_emp": int(getattr(args, "emp", 0)),
            "md_no_br": int(vf.get("md_no_br", 0)),
            "ext_th": vf.get("ext_th_d", {}),
            "sb_lg": listing_config.get("sb_lg", ""),
            "sb_md": listing_config.get("sb_md", ""),
            "sba_md": vf.get("md_sba", ""),
            "sba_lg": vf.get("lg_sba", ""),
            "txt_ext": getattr(args, "textfiles", "txt").replace(",", " "),
            "def_hcols": list(vf.get("mth", [])),
            "unlist0": vf.get("unlist", ""),
            "see_dots": getattr(args, "see_dots", False),
            "dqdel": getattr(args, "qdel", False),
            "dlni": listing_config.get("dlni", False),
            "dgrid": listing_config.get("dgrid", False),
            "dgsel": "gsel" in vf,
            "dnsort": "nsort" in vf,
            "dhsortn": vf.get("hsortn", ""),
            "dsort": vf.get("sort", "n"),
            "dcrop": vf.get("crop", ""),
            "dth3x": vf.get("th3x", ""),
            "drcm": getattr(args, "rcm", False),
            "dvol": getattr(args, "au_vol", 0.8),
            "idxh": int(getattr(args, "ih", 0)),
            "dutc": not getattr(args, "localtime", False),
            "dfszf": getattr(args, "ui_filesz", "").strip("-"),
            "themes": getattr(args, "themes", ""),
            "turbolvl": getattr(args, "turbo", 0),
            "nosubtle": getattr(args, "nosubtle", False),
            "u2j": getattr(args, "u2j", False),
        }

        return config

    def build_all_volume_configs(
        self,
        vfs: Any,
        args: Any,
        enshare: bool = False,
    ) -> tuple:
        """Build configuration for all volumes.

        Args:
            vfs: Root VFS node
            args: Command-line arguments
            enshare: Whether shares are enabled

        Returns:
            Tuple of (js_ls_dict, js_htm_dict) mapping vpath -> config
        """
        js_ls = {}
        js_htm = {}

        for vp, vn in vfs.all_nodes.items():
            # Skip shares in this iteration (handled separately)
            if enshare and vp.startswith(getattr(args, "shr", "") + "/"):
                continue

            vf = vn.flags
            listing_config = self.build_volume_listing_config(vn, vf)
            vn.js_ls = listing_config
            js_ls[vp] = listing_config

            html_config = self.build_volume_html_config(vn, vf, args, listing_config)
            js_htm[vp] = html_config

        return js_ls, js_htm
