"""PyQt5 GUI wrapper for Volatility 3."""

from __future__ import annotations

import csv
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib import parse, request

from PyQt5 import QtCore, QtGui, QtWidgets


APP_TITLE = "Volatility3 GUI for grze0"
MAX_TABLE_ROWS = 15000
RECENT_LIMIT = 10
MEMORY_REQUIRED_PREFIXES = {"windows", "linux", "mac"}
MODE_CLI = "CLI"
MODE_ANALYSIS = "Analysis"
MODE_TO_RENDERER = {
    MODE_CLI: "",
    MODE_ANALYSIS: "json",
}
COLUMN_PRIORITY = [
    "Offset",
    "PID",
    "PPID",
    "TID",
    "Process",
    "ImageFileName",
    "Name",
    "Path",
    "Variable",
    "Value",
    "Banner",
]
RUN_STAGE_READY = "ready"
RUN_STAGE_RUNNING = "running"
RUN_STAGE_DONE = "done"
MAX_EXPORT_TXT_ROWS = 3000
MAX_EXPORT_TEXT_WIDTH = 80
MAX_STREAM_PREVIEW_CHARS = 300000
MAX_CLI_UI_CHARS = 0  # 0 means unlimited (read full file)
MAX_ANALYSIS_PARSE_BYTES = 25 * 1024 * 1024
MAX_ANALYSIS_PARSE_ROWS = 60000


@dataclass
class PluginOption:
    flags: str
    description: str
    flag: str
    takes_value: bool
    multi_value: bool
    path_like: bool
    dir_like: bool = False
    optional: bool = True
    value_kind: str = "string"
    element_kind: str = ""
    choices: List[str] = field(default_factory=list)


@dataclass
class PluginDef:
    name: str
    summary: str
    usage: str
    category: str
    deprecated: bool = False
    required_flags: List[str] = field(default_factory=list)
    options: List[PluginOption] = field(default_factory=list)
    details_loaded: bool = False


class AsyncWorker(QtCore.QObject):
    finished = QtCore.pyqtSignal(int, object, object)

    def __init__(self, job_id: int, func):
        super().__init__()
        self._job_id = job_id
        self._func = func

    @QtCore.pyqtSlot()
    def run(self) -> None:
        try:
            result = self._func()
            self.finished.emit(self._job_id, result, None)
        except Exception as exc:
            self.finished.emit(self._job_id, None, str(exc))


class VolatilityCatalog:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.plugins: Dict[str, PluginDef] = {}
        self.plugin_classes: Dict[str, Any] = {}
        self.library_enabled = False
        self.library_error: Optional[str] = None

    def load(self) -> Tuple[List[PluginDef], Optional[str]]:
        plugins, warning = self._load_from_library()
        if plugins:
            return plugins, warning

        plugins, help_warning = self._load_from_help()
        warnings: List[str] = []
        if self.library_error:
            warnings.append(f"Library mode unavailable: {self.library_error}")
        if help_warning:
            warnings.append(help_warning)
        merged_warning = "; ".join(warnings) if warnings else None
        return plugins, merged_warning

    def ensure_details(self, plugin_name: str) -> Tuple[Optional[PluginDef], Optional[str]]:
        plugin = self.plugins.get(plugin_name)
        if plugin is None:
            return None, f"Plugin not found: {plugin_name}"
        if plugin.details_loaded:
            return plugin, None

        code, stdout, stderr = self._run_vol([plugin_name, "--help"])
        if code != 0:
            return plugin, (stderr.strip() or stdout.strip() or f"{plugin_name} --help failed")

        usage, description, options = self._parse_plugin_help(stdout)
        if usage and not plugin.usage:
            plugin.usage = usage
            plugin.required_flags = self._extract_required_flags(usage)
        if description and not plugin.summary:
            plugin.summary = description
            plugin.deprecated = "(deprecated" in plugin.summary.lower()
        plugin.options = options
        plugin.details_loaded = True
        return plugin, None

    def has_library_backend(self) -> bool:
        return self.library_enabled

    def preflight_unsatisfied(
        self,
        plugin_name: str,
        plugin_values: Dict[str, Any],
        memory_file: str,
        global_settings: Dict[str, Any],
    ) -> Tuple[List[str], Optional[str]]:
        if not self.library_enabled:
            return [], "Volatility library backend unavailable; using CLI fallback checks."

        try:
            import volatility3.plugins as vol_plugins
            import volatility3.symbols as vol_symbols
            from volatility3 import framework
            from volatility3.framework import automagic, constants, contexts, interfaces
            from volatility3.framework.automagic import stacker
            from volatility3.framework.configuration import requirements
        except Exception as exc:
            return [], f"Library preflight import failed: {exc}"

        plugin = self.plugin_classes.get(plugin_name)
        if plugin is None:
            return [], f"Plugin class not found in library catalog: {plugin_name}"

        try:
            plugin_dirs_text = str(global_settings.get("plugin_dirs", "")).strip()
            symbol_dirs_text = str(global_settings.get("symbol_dirs", "")).strip()
            cache_path = str(global_settings.get("cache_path", "")).strip()
            offline = bool(global_settings.get("offline"))
            clear_cache = bool(global_settings.get("clear_cache"))
            parallelism = str(global_settings.get("parallelism", "off")).strip().lower()
            original_plugins_path = list(vol_plugins.__path__)
            original_symbols_path = list(vol_symbols.__path__)
            original_cache_path = constants.CACHE_PATH
            original_offline = constants.OFFLINE
            original_parallelism = constants.PARALLELISM

            try:
                if plugin_dirs_text:
                    custom_paths = [os.path.abspath(item.strip()) for item in plugin_dirs_text.split(";") if item.strip()]
                    vol_plugins.__path__ = custom_paths + constants.PLUGINS_PATH
                if symbol_dirs_text:
                    custom_paths = [os.path.abspath(item.strip()) for item in symbol_dirs_text.split(";") if item.strip()]
                    vol_symbols.__path__ = custom_paths + constants.SYMBOL_BASEPATHS
                if cache_path:
                    constants.CACHE_PATH = cache_path
                if clear_cache:
                    framework.clear_cache()
                constants.OFFLINE = bool(offline)

                if parallelism == "processes":
                    constants.PARALLELISM = constants.Parallelism.Multiprocessing
                elif parallelism == "threads":
                    constants.PARALLELISM = constants.Parallelism.Threading
                else:
                    constants.PARALLELISM = constants.Parallelism.Off

                framework.import_files(vol_plugins, True)
                ctx = contexts.Context()
                automagics = automagic.available(ctx)
                automagics = automagic.choose_automagic(automagics, plugin)

                base_config_path = "plugins"
                plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)

                if memory_file:
                    ctx.config["automagic.LayerStacker.single_location"] = requirements.URIRequirement.location_from_file(
                        memory_file
                    )

                single_location = str(global_settings.get("single_location", "")).strip()
                if single_location:
                    parsed = parse.urlparse(single_location, "")
                    if parsed.scheme and len(parsed.scheme) > 1:
                        ctx.config["automagic.LayerStacker.single_location"] = single_location
                    else:
                        ctx.config["automagic.LayerStacker.single_location"] = requirements.URIRequirement.location_from_file(
                            single_location
                        )

                stackers_values = global_settings.get("stackers", [])
                if stackers_values:
                    ctx.config["automagic.LayerStacker.stackers"] = stackers_values
                elif ctx.config.get("automagic.LayerStacker.stackers", None) is None:
                    ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin)

                req_by_name = {req.name: req for req in plugin.get_requirements()}
                for req_name, value in plugin_values.items():
                    req = req_by_name.get(req_name)
                    if req is None:
                        continue
                    config_path = interfaces.configuration.path_join(plugin_config_path, req.name)
                    if isinstance(req, requirements.URIRequirement) and isinstance(value, str):
                        scheme = parse.urlparse(value).scheme
                        if not scheme or len(scheme) <= 1:
                            if not os.path.exists(value):
                                raise FileNotFoundError(f"Non-existent file {value} passed to URI requirement {req.name}")
                            value = "file://" + request.pathname2url(os.path.abspath(value))
                    ctx.config[config_path] = value

                automagic.run(automagics, ctx, plugin, base_config_path, progress_callback=lambda _f, _s=None: None)
                unsatisfied = plugin.unsatisfied(ctx, plugin_config_path)
                issues = []
                for config_path, requirement in sorted(unsatisfied.items()):
                    description = requirement.description or requirement.__class__.__name__
                    issues.append(f"{config_path}: {description}")
                return issues, None
            finally:
                vol_plugins.__path__ = original_plugins_path
                vol_symbols.__path__ = original_symbols_path
                constants.CACHE_PATH = original_cache_path
                constants.OFFLINE = original_offline
                constants.PARALLELISM = original_parallelism
        except Exception as exc:
            return [], f"Library preflight failed: {exc}"

    def _load_from_library(self) -> Tuple[List[PluginDef], Optional[str]]:
        try:
            if str(self.root_dir) not in sys.path:
                sys.path.insert(0, str(self.root_dir))

            import volatility3.plugins as vol_plugins
            from volatility3 import framework
            from volatility3.framework.configuration import requirements
        except Exception as exc:
            self.library_enabled = False
            self.library_error = str(exc)
            return [], None

        failures = framework.import_files(vol_plugins, True)
        plugin_classes = framework.list_plugins()
        plugins: Dict[str, PluginDef] = {}
        for name, plugin_class in plugin_classes.items():
            summary = ""
            if plugin_class.__doc__:
                summary = plugin_class.__doc__.split("\n\n", 1)[0].strip()
            options = self._options_from_requirements(plugin_class, requirements)
            required_flags = [opt.flag for opt in options if not opt.optional]
            category = name.split(".", 1)[0] if "." in name else "core"
            plugins[name] = PluginDef(
                name=name,
                summary=summary,
                usage=f"usage: vol.py {name} [options]",
                category=category,
                deprecated="(deprecated" in summary.lower(),
                required_flags=required_flags,
                options=options,
                details_loaded=True,
            )

        self.library_enabled = True
        self.library_error = None
        self.plugin_classes = plugin_classes
        self.plugins = plugins

        warning = None
        if failures:
            warning = "Some plugins could not be imported in library mode."
        return sorted(self.plugins.values(), key=lambda p: p.name), warning

    def _options_from_requirements(self, plugin_class, requirements_module) -> List[PluginOption]:
        options: List[PluginOption] = []
        for requirement in plugin_class.get_requirements():
            flag = f"--{requirement.name.replace('_', '-')}"
            description = str(getattr(requirement, "description", "") or "").strip()
            optional = bool(getattr(requirement, "optional", True))
            value_kind = "string"
            element_kind = ""
            choices: List[str] = []
            takes_value = True
            multi_value = False
            path_like = False
            dir_like = False
            flags = flag

            if isinstance(requirement, requirements_module.BooleanRequirement):
                takes_value = False
                value_kind = "bool"
            elif isinstance(requirement, requirements_module.IntRequirement):
                value_kind = "int"
                flags = f"{flag} INT"
            elif isinstance(requirement, requirements_module.URIRequirement):
                value_kind = "uri"
                path_like = True
                flags = f"{flag} URI"
            elif isinstance(requirement, requirements_module.StringRequirement):
                value_kind = "string"
                flags = f"{flag} STRING"
            elif isinstance(requirement, requirements_module.ChoiceRequirement):
                value_kind = "choice"
                choices = [str(choice) for choice in requirement.choices]
                flags = f"{flag} " + "{" + ",".join(choices) + "}"
            elif isinstance(requirement, requirements_module.ListRequirement):
                multi_value = True
                element_type = getattr(requirement, "element_type", str)
                element_kind = getattr(element_type, "__name__", str(element_type))
                if element_type is int:
                    value_kind = "int_list"
                    flags = f"{flag} [INT ...]"
                else:
                    value_kind = "string_list"
                    flags = f"{flag} [VALUE ...]"
            else:
                # Complex requirements (layer/symbol/module/version) are fulfilled by automagic/config, not direct flags.
                continue

            options.append(
                PluginOption(
                    flags=flags,
                    description=description,
                    flag=flag,
                    takes_value=takes_value,
                    multi_value=multi_value,
                    path_like=path_like,
                    dir_like=dir_like,
                    optional=optional,
                    value_kind=value_kind,
                    element_kind=element_kind,
                    choices=choices,
                )
            )
        return options

    def _load_from_help(self) -> Tuple[List[PluginDef], Optional[str]]:
        code, stdout, stderr = self._run_vol(["-h"])
        if code != 0:
            return [], (stderr.strip() or stdout.strip() or "vol.py -h failed")

        plugins = self._parse_plugins_from_top_help(stdout)
        self.plugins = {p.name: p for p in plugins}
        return sorted(self.plugins.values(), key=lambda p: p.name), None

    def _run_vol(self, args: List[str], timeout: int = 25) -> Tuple[int, str, str]:
        try:
            process = subprocess.run(
                [sys.executable, "vol.py", *args],
                cwd=self.root_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            return process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as exc:
            stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
            stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            return 124, stdout, stderr or "vol.py call timed out"

    def _parse_plugins_from_top_help(self, text: str) -> List[PluginDef]:
        lines = text.splitlines()
        start = self._find_line(lines, "PLUGIN")
        if start < 0:
            return []

        plugins: List[PluginDef] = []
        current_name = ""
        current_desc = ""

        for line in lines[start + 1 :]:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("The following plugins could not be loaded"):
                break

            match = re.match(r"^\s{4}([A-Za-z0-9_.]+)\s*(.*)$", line)
            if match:
                if current_name:
                    category = current_name.split(".", 1)[0] if "." in current_name else "core"
                    plugins.append(
                        PluginDef(
                            name=current_name,
                            summary=current_desc.strip(),
                            usage="",
                            category=category,
                            deprecated="(deprecated" in current_desc.lower(),
                            required_flags=[],
                            options=[],
                            details_loaded=False,
                        )
                    )
                current_name = match.group(1).strip()
                current_desc = match.group(2).strip()
                continue

            if current_name and line.startswith(" "):
                tail = line.strip()
                if tail:
                    current_desc = f"{current_desc} {tail}".strip()

        if current_name:
            category = current_name.split(".", 1)[0] if "." in current_name else "core"
            plugins.append(
                PluginDef(
                    name=current_name,
                    summary=current_desc.strip(),
                    usage="",
                    category=category,
                    deprecated="(deprecated" in current_desc.lower(),
                    required_flags=[],
                    options=[],
                    details_loaded=False,
                )
            )

        unique: List[PluginDef] = []
        seen = set()
        for plugin in plugins:
            if plugin.name in seen:
                continue
            seen.add(plugin.name)
            unique.append(plugin)
        return unique

    def _parse_plugin_help(self, text: str) -> Tuple[str, str, List[PluginOption]]:
        lines = text.splitlines()
        usage = lines[0].strip() if lines else ""

        description = ""
        for line in lines[1:]:
            if line.strip():
                if line.strip().lower() == "options:":
                    break
                description = line.strip()
                break

        options_start = self._find_line(lines, "options:")
        if options_start < 0:
            return usage, description, []
        options = self._parse_option_lines(lines[options_start + 1 :])
        return usage, description, options
    def _parse_option_lines(self, lines: List[str]) -> List[PluginOption]:
        options: List[PluginOption] = []
        current_flags = ""
        current_desc = ""

        for line in lines:
            if not line.strip():
                continue

            if re.match(r"^\s{2}-", line):
                if current_flags:
                    options.append(self._make_option(current_flags, current_desc.strip()))
                body = line.strip()
                parts = re.split(r"\s{2,}", body, maxsplit=1)
                current_flags = parts[0].strip()
                current_desc = parts[1].strip() if len(parts) > 1 else ""
                continue

            if current_flags and line.startswith(" "):
                tail = line.strip()
                if tail:
                    current_desc = f"{current_desc} {tail}".strip()

        if current_flags:
            options.append(self._make_option(current_flags, current_desc.strip()))
        return options

    def _make_option(self, flags: str, description: str) -> PluginOption:
        chunks = [chunk.strip() for chunk in flags.split(",") if chunk.strip()]
        chosen = chunks[-1] if chunks else flags.strip()
        for chunk in reversed(chunks):
            if chunk.startswith("--"):
                chosen = chunk
                break

        parts = chosen.split(maxsplit=1)
        flag = parts[0]
        hint = parts[1] if len(parts) > 1 else ""
        takes_value = bool(hint)
        multi_value = "..." in hint
        text = f"{flags} {description}".upper()
        path_like = any(token in text for token in ("FILE", "PATH", "DIR", "URI", "LOCATION", "ISF"))
        dir_like = any(token in text for token in ("DIR", "DIRECTORY", "FOLDER"))

        return PluginOption(
            flags=flags,
            description=description,
            flag=flag,
            takes_value=takes_value,
            multi_value=multi_value,
            path_like=path_like,
            dir_like=dir_like,
            optional=True,
            value_kind="string_list" if multi_value else "string",
        )

    def _extract_required_flags(self, usage: str) -> List[str]:
        if not usage:
            return []
        # argparse usage puts optional groups inside [].
        outside = []
        depth = 0
        for ch in usage:
            if ch == "[":
                depth += 1
                continue
            if ch == "]":
                depth = max(0, depth - 1)
                continue
            if depth == 0:
                outside.append(ch)
        text = "".join(outside)
        flags = re.findall(r"--[a-zA-Z0-9][a-zA-Z0-9_-]*", text)
        unique = []
        seen = set()
        for flag in flags:
            if flag in seen:
                continue
            seen.add(flag)
            unique.append(flag)
        return unique

    @staticmethod
    def _find_line(lines: List[str], target: str) -> int:
        for index, line in enumerate(lines):
            if line.strip().lower() == target.lower():
                return index
        return -1


class VolGuiWindow(QtWidgets.QMainWindow):
    def __init__(self, root_dir: Path):
        super().__init__()
        self.root_dir = root_dir
        self.output_base = self.root_dir / "volgui_output"
        self.state_path = self.root_dir / ".volgui_state.json"
        self.catalog = VolatilityCatalog(root_dir)
        self.profile_path = self._resolve_profile_path()

        self.plugins: List[PluginDef] = []
        self.selected_plugin: Optional[PluginDef] = None
        self.option_controls: List[Tuple[PluginOption, QtWidgets.QWidget]] = []
        self._active_threads: List[QtCore.QThread] = []
        self._async_jobs: Dict[int, Tuple[Any, Any, QtCore.QThread, AsyncWorker]] = {}
        self._next_async_job_id = 0
        self._details_request_id = 0
        self._preflight_request_id = 0
        self._run_serial = 0
        self._active_run_serial = 0
        self.run_stage = RUN_STAGE_READY

        self.process: Optional[QtCore.QProcess] = None
        self.current_command: List[str] = []
        self.current_output_dir: Optional[Path] = None
        self.run_started_at = 0.0
        self.run_mode = MODE_CLI
        self.stdout_preview = ""
        self.stderr_preview = ""
        self.stdout_stream_path: Optional[Path] = None
        self.stderr_stream_path: Optional[Path] = None
        self.stdout_stream_handle = None
        self.stderr_stream_handle = None

        self.recent_files: List[str] = []
        self.loaded_row_count = 0

        self._build_ui()
        self._apply_theme()
        self._set_run_stage(RUN_STAGE_READY)
        self._load_state()
        self._load_plugins_async()
        self._on_mode_changed(self._current_mode())
        self._update_command_preview()

    def _build_ui(self) -> None:
        self.setWindowTitle(APP_TITLE)
        self.resize(1500, 920)
        self.setMinimumSize(1220, 760)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root_layout = QtWidgets.QVBoxLayout(central)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)

        header = QtWidgets.QFrame()
        header.setObjectName("headerCard")
        header_layout = QtWidgets.QVBoxLayout(header)
        header_layout.setContentsMargins(14, 12, 14, 12)
        header_layout.setSpacing(10)

        title_row = QtWidgets.QHBoxLayout()
        self.logo_label = QtWidgets.QLabel()
        self.logo_label.setFixedSize(42, 42)
        self.logo_label.setObjectName("logo")
        title_col = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel("Volatility3 GUI for grze0")
        title.setObjectName("title")
        subtitle = QtWidgets.QLabel("CLI and Analysis modes")
        subtitle.setObjectName("subtitle")
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        title_row.addWidget(self.logo_label)
        title_row.addLayout(title_col, 1)
        title_row.addStretch(1)
        self._load_logo()
        header_layout.addLayout(title_row)

        mem_row = QtWidgets.QHBoxLayout()
        mem_row.addWidget(QtWidgets.QLabel("Memory File"), 0)
        self.memory_edit = QtWidgets.QLineEdit()
        self.memory_edit.setPlaceholderText("Select memory dump file...")
        mem_row.addWidget(self.memory_edit, 1)
        browse_btn = QtWidgets.QPushButton("Browse")
        browse_btn.clicked.connect(self._choose_memory_file)
        mem_row.addWidget(browse_btn, 0)
        mem_row.addWidget(QtWidgets.QLabel("Recent"), 0)
        self.recent_combo = QtWidgets.QComboBox()
        self.recent_combo.setMinimumWidth(360)
        self.recent_combo.currentTextChanged.connect(self._on_recent_selected)
        mem_row.addWidget(self.recent_combo, 0)
        mem_row.addWidget(QtWidgets.QLabel("Mode"), 0)
        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems([MODE_CLI, MODE_ANALYSIS])
        self.mode_combo.setCurrentText(MODE_CLI)
        self.mode_combo.currentTextChanged.connect(self._on_mode_changed)
        mem_row.addWidget(self.mode_combo, 0)
        self.show_deprecated_check = QtWidgets.QCheckBox("Show deprecated")
        self.show_deprecated_check.setChecked(False)
        self.show_deprecated_check.stateChanged.connect(self._refresh_plugin_tree)
        mem_row.addWidget(self.show_deprecated_check, 0)
        header_layout.addLayout(mem_row)

        self.advanced_toggle = QtWidgets.QToolButton()
        self.advanced_toggle.setObjectName("advancedToggle")
        self.advanced_toggle.setCheckable(True)
        self.advanced_toggle.setChecked(False)
        self.advanced_toggle.setText("Show Advanced Options")
        self.advanced_toggle.clicked.connect(self._on_advanced_options_toggled)
        header_layout.addWidget(self.advanced_toggle)

        self.global_options_box = QtWidgets.QFrame()
        self.global_options_box.setObjectName("globalOptionsBox")
        global_layout = QtWidgets.QGridLayout(self.global_options_box)
        global_layout.setContentsMargins(8, 8, 8, 8)
        global_layout.setHorizontalSpacing(8)
        global_layout.setVerticalSpacing(6)

        global_layout.addWidget(QtWidgets.QLabel("Parallel"), 0, 0)
        self.parallel_combo = QtWidgets.QComboBox()
        self.parallel_combo.addItems(["off", "threads", "processes"])
        self.parallel_combo.currentTextChanged.connect(self._update_command_preview)
        global_layout.addWidget(self.parallel_combo, 0, 1)

        self.quiet_check = QtWidgets.QCheckBox("Quiet (-q)")
        self.quiet_check.setChecked(False)
        self.quiet_check.stateChanged.connect(self._update_command_preview)
        global_layout.addWidget(self.quiet_check, 0, 2)

        self.offline_check = QtWidgets.QCheckBox("Offline symbols")
        self.offline_check.setChecked(False)
        self.offline_check.stateChanged.connect(self._update_command_preview)
        global_layout.addWidget(self.offline_check, 0, 3)

        self.clear_cache_check = QtWidgets.QCheckBox("Clear cache before run")
        self.clear_cache_check.setChecked(False)
        self.clear_cache_check.stateChanged.connect(self._update_command_preview)
        global_layout.addWidget(self.clear_cache_check, 0, 4)

        global_layout.addWidget(QtWidgets.QLabel("Plugin Dirs"), 1, 0)
        self.plugin_dirs_edit = QtWidgets.QLineEdit()
        self.plugin_dirs_edit.setPlaceholderText("Semi-colon separated paths")
        self.plugin_dirs_edit.textChanged.connect(self._on_global_option_changed)
        global_layout.addWidget(self.plugin_dirs_edit, 1, 1, 1, 2)

        global_layout.addWidget(QtWidgets.QLabel("Symbol Dirs"), 1, 3)
        self.symbol_dirs_edit = QtWidgets.QLineEdit()
        self.symbol_dirs_edit.setPlaceholderText("Semi-colon separated paths")
        self.symbol_dirs_edit.textChanged.connect(self._on_global_option_changed)
        global_layout.addWidget(self.symbol_dirs_edit, 1, 4, 1, 2)

        global_layout.addWidget(QtWidgets.QLabel("Single Location"), 2, 0)
        self.single_location_edit = QtWidgets.QLineEdit()
        self.single_location_edit.setPlaceholderText("URI or local path")
        self.single_location_edit.textChanged.connect(self._update_command_preview)
        global_layout.addWidget(self.single_location_edit, 2, 1, 1, 2)

        global_layout.addWidget(QtWidgets.QLabel("Stackers"), 2, 3)
        self.stackers_edit = QtWidgets.QLineEdit()
        self.stackers_edit.setPlaceholderText("space/comma separated stackers")
        self.stackers_edit.textChanged.connect(self._update_command_preview)
        global_layout.addWidget(self.stackers_edit, 2, 4, 1, 2)

        global_layout.addWidget(QtWidgets.QLabel("Cache Path"), 3, 0)
        self.cache_path_edit = QtWidgets.QLineEdit()
        self.cache_path_edit.setPlaceholderText("Optional cache directory")
        self.cache_path_edit.textChanged.connect(self._update_command_preview)
        global_layout.addWidget(self.cache_path_edit, 3, 1, 1, 2)

        self.plugin_dir_warning = QtWidgets.QLabel("")
        self.plugin_dir_warning.setObjectName("warningLabel")
        self.plugin_dir_warning.setWordWrap(True)
        global_layout.addWidget(self.plugin_dir_warning, 3, 3, 1, 3)
        self.global_options_box.setVisible(False)
        header_layout.addWidget(self.global_options_box)

        action_row = QtWidgets.QHBoxLayout()
        self.command_preview = QtWidgets.QLineEdit()
        self.command_preview.setReadOnly(True)
        action_row.addWidget(self.command_preview, 1)
        self.run_btn = QtWidgets.QPushButton("Run")
        self.run_btn.clicked.connect(self._run_analysis)
        action_row.addWidget(self.run_btn, 0)
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_analysis)
        action_row.addWidget(self.stop_btn, 0)
        self.open_output_btn = QtWidgets.QPushButton("Open Output")
        self.open_output_btn.clicked.connect(self._open_output_dir)
        action_row.addWidget(self.open_output_btn, 0)
        header_layout.addLayout(action_row)

        status_row = QtWidgets.QHBoxLayout()
        status_row.setContentsMargins(0, 0, 0, 0)
        status_row.setSpacing(6)
        self.status_label = QtWidgets.QLabel("Ready")
        self.status_label.setObjectName("status")
        status_row.addWidget(self.status_label, 1)

        self.run_stage_label = QtWidgets.QLabel("")
        self.run_stage_label.setObjectName("runStage")
        self.run_stage_label.setSizePolicy(
            QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed
        )
        status_row.addWidget(self.run_stage_label, 0, QtCore.Qt.AlignRight)
        header_layout.addLayout(status_row)

        root_layout.addWidget(header)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        root_layout.addWidget(splitter, 1)
        # Left: plugin list
        left = QtWidgets.QFrame()
        left_layout = QtWidgets.QVBoxLayout(left)
        left_layout.setContentsMargins(10, 10, 10, 10)
        left_layout.setSpacing(8)
        self.plugin_search = QtWidgets.QLineEdit()
        self.plugin_search.setPlaceholderText("Search plugin...")
        self.plugin_search.textChanged.connect(self._refresh_plugin_tree)
        left_layout.addWidget(self.plugin_search)
        self.plugin_tree = QtWidgets.QTreeWidget()
        self.plugin_tree.setHeaderHidden(True)
        self.plugin_tree.itemSelectionChanged.connect(self._on_plugin_selected)
        left_layout.addWidget(self.plugin_tree, 1)
        splitter.addWidget(left)

        # Center: plugin details + options
        center = QtWidgets.QFrame()
        center_layout = QtWidgets.QVBoxLayout(center)
        center_layout.setContentsMargins(10, 10, 10, 10)
        center_layout.setSpacing(8)
        self.plugin_title = QtWidgets.QLabel("Select a plugin")
        self.plugin_title.setObjectName("panelTitle")
        center_layout.addWidget(self.plugin_title)
        self.plugin_detail = QtWidgets.QPlainTextEdit()
        self.plugin_detail.setReadOnly(True)
        self.plugin_detail.setMaximumHeight(175)
        center_layout.addWidget(self.plugin_detail)
        self.options_scroll = QtWidgets.QScrollArea()
        self.options_scroll.setWidgetResizable(True)
        self.options_content = QtWidgets.QWidget()
        self.options_layout = QtWidgets.QVBoxLayout(self.options_content)
        self.options_layout.setContentsMargins(0, 0, 0, 0)
        self.options_layout.setSpacing(8)
        self.options_scroll.setWidget(self.options_content)
        center_layout.addWidget(self.options_scroll, 1)
        splitter.addWidget(center)

        # Right: results + search + execution log
        right = QtWidgets.QFrame()
        right_layout = QtWidgets.QVBoxLayout(right)
        right_layout.setContentsMargins(10, 10, 10, 10)
        right_layout.setSpacing(8)

        result_header = QtWidgets.QHBoxLayout()
        result_header.addWidget(QtWidgets.QLabel("Result Search"), 0)
        self.result_search = QtWidgets.QLineEdit()
        self.result_search.setPlaceholderText("Type to filter all table columns...")
        self.result_search.textChanged.connect(self._apply_result_filter)
        result_header.addWidget(self.result_search, 1)
        self.result_count_label = QtWidgets.QLabel("Rows: 0")
        result_header.addWidget(self.result_count_label, 0)
        right_layout.addLayout(result_header)

        right_split = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        right_split.setChildrenCollapsible(False)

        self.result_stack = QtWidgets.QStackedWidget()
        mono = QtGui.QFont("Consolas")
        mono.setStyleHint(QtGui.QFont.Monospace)

        table_page = QtWidgets.QWidget()
        table_layout = QtWidgets.QVBoxLayout(table_page)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(6)
        self.table_view = QtWidgets.QTreeView()
        self.table_model = QtGui.QStandardItemModel(self)
        self.table_proxy = QtCore.QSortFilterProxyModel(self)
        self.table_proxy.setSourceModel(self.table_model)
        self.table_proxy.setFilterCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.table_proxy.setFilterKeyColumn(-1)
        if hasattr(self.table_proxy, "setRecursiveFilteringEnabled"):
            self.table_proxy.setRecursiveFilteringEnabled(True)
        self.table_proxy.setSortRole(QtCore.Qt.UserRole)
        self.table_view.setModel(self.table_proxy)
        self.table_view.setSortingEnabled(True)
        self.table_view.setRootIsDecorated(True)
        self.table_view.setItemsExpandable(True)
        self.table_view.header().setStretchLastSection(True)
        self.table_view.setAlternatingRowColors(True)

        analysis_split = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        analysis_split.setChildrenCollapsible(False)
        analysis_split.addWidget(self.table_view)

        raw_panel = QtWidgets.QFrame()
        raw_layout = QtWidgets.QVBoxLayout(raw_panel)
        raw_layout.setContentsMargins(0, 0, 0, 0)
        raw_layout.setSpacing(4)
        raw_label = QtWidgets.QLabel("Analysis Raw Output (live)")
        raw_layout.addWidget(raw_label)
        self.analysis_raw_box = QtWidgets.QPlainTextEdit()
        self.analysis_raw_box.setReadOnly(True)
        self.analysis_raw_box.setPlaceholderText("Raw stdout stream will appear here during Analysis mode.")
        self.analysis_raw_box.setFont(mono)
        self.analysis_raw_box.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.analysis_raw_box.setTabStopDistance(32)
        raw_layout.addWidget(self.analysis_raw_box, 1)
        analysis_split.addWidget(raw_panel)
        analysis_split.setSizes([460, 170])
        table_layout.addWidget(analysis_split, 1)

        cli_page = QtWidgets.QWidget()
        cli_layout = QtWidgets.QVBoxLayout(cli_page)
        cli_layout.setContentsMargins(0, 0, 0, 0)
        cli_layout.setSpacing(0)
        self.cli_result_box = QtWidgets.QPlainTextEdit()
        self.cli_result_box.setReadOnly(True)
        self.cli_result_box.setPlaceholderText("CLI output will appear here.")
        self.cli_result_box.setFont(mono)
        self.cli_result_box.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.cli_result_box.setTabStopDistance(32)
        cli_layout.addWidget(self.cli_result_box)

        self.result_stack.addWidget(table_page)
        self.result_stack.addWidget(cli_page)
        right_split.addWidget(self.result_stack)

        self.bottom_tabs = QtWidgets.QTabWidget()
        log_tab = QtWidgets.QWidget()
        log_layout = QtWidgets.QVBoxLayout(log_tab)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.setSpacing(0)
        self.log_box = QtWidgets.QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFont(mono)
        self.log_box.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.log_box.setTabStopDistance(32)
        log_layout.addWidget(self.log_box)
        self.bottom_tabs.addTab(log_tab, "Execution Log")

        files_tab = QtWidgets.QWidget()
        files_layout = QtWidgets.QVBoxLayout(files_tab)
        files_layout.setContentsMargins(0, 0, 0, 0)
        files_layout.setSpacing(6)
        self.generated_files_list = QtWidgets.QListWidget()
        self.generated_files_list.itemDoubleClicked.connect(self._open_selected_generated_file)
        files_layout.addWidget(self.generated_files_list, 1)
        files_actions = QtWidgets.QHBoxLayout()
        self.open_generated_file_btn = QtWidgets.QPushButton("Open Selected File")
        self.open_generated_file_btn.clicked.connect(self._open_selected_generated_file)
        files_actions.addWidget(self.open_generated_file_btn, 0)
        files_actions.addStretch(1)
        files_layout.addLayout(files_actions)
        self.bottom_tabs.addTab(files_tab, "Generated Files")

        right_split.addWidget(self.bottom_tabs)
        right_split.setSizes([560, 230])

        right_layout.addWidget(right_split, 1)
        splitter.addWidget(right)

        splitter.setSizes([330, 520, 650])

        self.memory_edit.textChanged.connect(self._update_command_preview)
        self._update_plugin_dir_warning()

    def _apply_theme(self) -> None:
        self.setStyleSheet(
            """
            QWidget {
                font-family: "Segoe UI";
                font-size: 13px;
                color: #21303f;
                background: #edf1f5;
            }
            QFrame#headerCard {
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 1, y2: 1,
                    stop: 0 #f8fbfe,
                    stop: 1 #e9eef4
                );
                border: 1px solid #c9d4df;
                border-radius: 10px;
            }
            QLabel#logo {
                background: #d7e2ef;
                border: 1px solid #b7c6d6;
                border-radius: 21px;
            }
            QFrame#globalOptionsBox {
                background: #f6f9fc;
                border: 1px solid #ccd7e2;
                border-radius: 8px;
            }
            QLabel#title {
                font-size: 19px;
                font-weight: 600;
                color: #1b2a3a;
            }
            QLabel#subtitle {
                color: #58697c;
            }
            QLabel#status {
                color: #3c5064;
            }
            QLabel#runStage {
                color: #32485d;
                background: #f7fafc;
                border: 1px solid #ced9e4;
                border-radius: 10px;
                padding: 1px 6px;
                font-size: 10px;
                font-weight: 500;
            }
            QLabel#panelTitle {
                font-size: 15px;
                font-weight: 600;
                color: #23364b;
            }
            QLabel#warningLabel {
                color: #8a3d00;
                background: #fff3e8;
                border: 1px solid #f0cca8;
                border-radius: 6px;
                padding: 4px 6px;
            }
            QLineEdit, QComboBox, QPlainTextEdit, QTreeWidget, QTreeView, QTableView {
                background: #ffffff;
                border: 1px solid #c6d0db;
                border-radius: 6px;
                padding: 5px;
            }
            QPushButton {
                background: #dfe8f1;
                border: 1px solid #bcc9d6;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background: #d3deea;
            }
            QPushButton:disabled {
                background: #edf2f6;
                color: #97a6b6;
            }
            QToolButton#advancedToggle {
                text-align: left;
                background: #e8eef5;
                border: 1px solid #c6d3e0;
                border-radius: 6px;
                padding: 5px 8px;
            }
            QToolButton#advancedToggle:hover {
                background: #dde7f1;
            }
            """
        )

    def _resolve_profile_path(self) -> Optional[Path]:
        search_dirs: List[Path] = []
        bundle_dir = getattr(sys, "_MEIPASS", None)
        if bundle_dir:
            search_dirs.append(Path(bundle_dir))
        if getattr(sys, "frozen", False):
            try:
                search_dirs.append(Path(sys.executable).resolve().parent)
            except Exception:
                pass
        search_dirs.extend([self.root_dir, self.root_dir.parent])

        preferred_names = ["profile.png", "grze0.png"]
        seen_dirs = set()
        for directory in search_dirs:
            key = str(directory)
            if key in seen_dirs:
                continue
            seen_dirs.add(key)
            for name in preferred_names:
                candidate = directory / name
                if candidate.exists():
                    return candidate
            try:
                for candidate in sorted(directory.glob("*.png")):
                    if candidate.exists():
                        return candidate
            except Exception:
                continue
        return None

    @staticmethod
    def _rounded_pixmap(source: QtGui.QPixmap, width: int, height: int, radius: float) -> QtGui.QPixmap:
        if source.isNull():
            return QtGui.QPixmap()
        cover = source.scaled(
            width,
            height,
            QtCore.Qt.KeepAspectRatioByExpanding,
            QtCore.Qt.SmoothTransformation,
        )
        target = QtGui.QPixmap(width, height)
        target.fill(QtCore.Qt.transparent)
        painter = QtGui.QPainter(target)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        path = QtGui.QPainterPath()
        path.addRoundedRect(QtCore.QRectF(0, 0, width, height), radius, radius)
        painter.setClipPath(path)
        painter.drawPixmap(0, 0, cover)
        painter.end()
        return target

    def _load_logo(self) -> None:
        if self.profile_path is not None:
            pix = QtGui.QPixmap(str(self.profile_path))
            if not pix.isNull():
                avatar = self._rounded_pixmap(pix, 42, 42, 21)
                self.logo_label.setPixmap(avatar)
                self.logo_label.setText("")
                self.setWindowIcon(QtGui.QIcon(pix))
                return
        self.logo_label.setText("V3")
        self.logo_label.setAlignment(QtCore.Qt.AlignCenter)

    def _on_advanced_options_toggled(self, checked: bool) -> None:
        self.global_options_box.setVisible(checked)
        self.advanced_toggle.setText(
            "Hide Advanced Options" if checked else "Show Advanced Options"
        )

    def _on_global_option_changed(self, _text: str) -> None:
        self._update_plugin_dir_warning()
        self._update_command_preview()

    def _update_plugin_dir_warning(self) -> None:
        plugin_dirs = self.plugin_dirs_edit.text().strip()
        if plugin_dirs:
            self.plugin_dir_warning.setText(
                "Security: custom plugin dirs execute Python code. Use only trusted paths."
            )
            self.plugin_dir_warning.setVisible(True)
        else:
            self.plugin_dir_warning.setText("")
            self.plugin_dir_warning.setVisible(False)

    def _set_run_stage(self, stage: str) -> None:
        if stage not in {RUN_STAGE_READY, RUN_STAGE_RUNNING, RUN_STAGE_DONE}:
            return
        self.run_stage = stage
        if stage == RUN_STAGE_READY:
            text = "Stage 1/3: Before"
        elif stage == RUN_STAGE_RUNNING:
            text = "Stage 2/3: Running"
        else:
            text = "Stage 3/3: Done"
        self.run_stage_label.setText(text)
        self.run_stage_label.setToolTip("Before -> Running -> Done")

    def _start_async(
        self,
        func,
        on_success,
        on_error=None,
    ) -> None:
        self._next_async_job_id += 1
        job_id = self._next_async_job_id
        thread = QtCore.QThread(self)
        worker = AsyncWorker(job_id, func)
        worker.moveToThread(thread)
        self._async_jobs[job_id] = (on_success, on_error, thread, worker)

        worker.finished.connect(self._on_async_finished, QtCore.Qt.QueuedConnection)
        worker.finished.connect(worker.deleteLater)
        thread.started.connect(worker.run)
        thread.finished.connect(thread.deleteLater)
        self._active_threads.append(thread)
        thread.start()

    @QtCore.pyqtSlot(int, object, object)
    def _on_async_finished(self, job_id: int, result: object, error: object) -> None:
        handlers = self._async_jobs.pop(job_id, None)
        if not handlers:
            return
        on_success, on_error, thread, _worker = handlers
        try:
            if error is None:
                on_success(result)
            elif on_error:
                on_error(str(error))
            else:
                self.status_label.setText(str(error))
        finally:
            if thread in self._active_threads:
                self._active_threads.remove(thread)
            if thread.isRunning():
                thread.quit()

    def _load_plugins_async(self) -> None:
        self.status_label.setText("Loading plugin catalog...")
        self.plugin_tree.setEnabled(False)
        self.run_btn.setEnabled(False)
        self._start_async(
            func=self.catalog.load,
            on_success=self._on_plugins_loaded,
            on_error=self._on_plugins_load_error,
        )

    def _on_plugins_loaded(self, payload) -> None:
        plugins, warning = payload
        self.plugins = plugins
        self._refresh_plugin_tree()
        self.plugin_tree.setEnabled(True)
        self.run_btn.setEnabled(True)
        message = f"Loaded {len(self.plugins)} plugins."
        if warning:
            message = f"{message} {warning}"
        elif self.catalog.library_error:
            message = f"{message} Library backend fallback active."
        self.status_label.setText(message)

    def _on_plugins_load_error(self, error: str) -> None:
        self.plugin_tree.setEnabled(True)
        self.run_btn.setEnabled(True)
        self.status_label.setText(f"Plugin load failed: {error}")

    def _refresh_plugin_tree(self) -> None:
        query = self.plugin_search.text().strip().lower()
        show_deprecated = self.show_deprecated_check.isChecked()
        grouped: Dict[str, List[PluginDef]] = {}
        for plugin in self.plugins:
            if plugin.deprecated and not show_deprecated:
                continue
            haystack = f"{plugin.name} {plugin.summary}".lower()
            if query and query not in haystack:
                continue
            grouped.setdefault(plugin.category, []).append(plugin)

        self.plugin_tree.clear()
        for category in sorted(grouped):
            parent = QtWidgets.QTreeWidgetItem([f"{category} ({len(grouped[category])})"])
            parent.setFlags(parent.flags() & ~QtCore.Qt.ItemIsSelectable)
            self.plugin_tree.addTopLevelItem(parent)
            for plugin in sorted(grouped[category], key=lambda p: p.name):
                item = QtWidgets.QTreeWidgetItem([plugin.name])
                item.setData(0, QtCore.Qt.UserRole, plugin.name)
                parent.addChild(item)
            parent.setExpanded(True)

    def _on_plugin_selected(self) -> None:
        items = self.plugin_tree.selectedItems()
        if not items:
            return
        plugin_name = items[0].data(0, QtCore.Qt.UserRole)
        if not plugin_name:
            return
        self._details_request_id += 1
        request_id = self._details_request_id
        self.status_label.setText(f"Loading plugin details: {plugin_name}")
        self.plugin_title.setText(plugin_name)
        self.plugin_detail.setPlainText("Loading plugin details...")
        self._clear_layout(self.options_layout)
        self.options_layout.addWidget(QtWidgets.QLabel("Loading plugin options..."))
        self.options_layout.addStretch(1)

        self._start_async(
            func=lambda name=plugin_name: self.catalog.ensure_details(name),
            on_success=lambda payload, rid=request_id, name=plugin_name: self._on_plugin_details_loaded(
                rid, name, payload
            ),
            on_error=lambda error, rid=request_id, name=plugin_name: self._on_plugin_details_error(
                rid, name, error
            ),
        )

    def _on_plugin_details_loaded(self, request_id: int, plugin_name: str, payload) -> None:
        if request_id != self._details_request_id:
            return
        current = self.plugin_tree.selectedItems()
        if not current:
            return
        selected_name = current[0].data(0, QtCore.Qt.UserRole)
        if selected_name != plugin_name:
            return

        plugin, error = payload
        if plugin is None:
            self.status_label.setText(error or "Failed to load plugin details.")
            return
        if error:
            self.status_label.setText(error)
        else:
            self.status_label.setText(f"Ready: {plugin.name}")
        self.selected_plugin = plugin
        self._render_plugin_details(plugin)
        self._render_option_controls(plugin.options)
        self._update_command_preview()

    def _on_plugin_details_error(self, request_id: int, plugin_name: str, error: str) -> None:
        if request_id != self._details_request_id:
            return
        self.status_label.setText(f"Plugin detail load failed: {plugin_name}: {error}")

    def _render_plugin_details(self, plugin: PluginDef) -> None:
        self.plugin_title.setText(plugin.name)
        usage = plugin.usage or f"usage: vol.py {plugin.name} [options]"
        summary = plugin.summary or "(no summary)"
        required = ", ".join(plugin.required_flags) if plugin.required_flags else "(none)"
        deprecated_note = "Yes" if plugin.deprecated else "No"
        text = (
            f"Description\n{summary}\n\n"
            f"Usage\n{usage}\n\n"
            f"Required options: {required}\n"
            f"Deprecated: {deprecated_note}\n"
            f"Option count: {len([opt for opt in plugin.options if opt.flag not in ('-h', '--help')])}"
        )
        self.plugin_detail.setPlainText(text)
    def _clear_layout(self, layout: QtWidgets.QLayout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            child_layout = item.layout()
            if widget is not None:
                widget.deleteLater()
            if child_layout is not None:
                self._clear_layout(child_layout)

    def _render_option_controls(self, options: List[PluginOption]) -> None:
        self._clear_layout(self.options_layout)
        self.option_controls.clear()
        required_flags = set(self.selected_plugin.required_flags if self.selected_plugin else [])

        filtered = [opt for opt in options if opt.flag not in ("-h", "--help")]
        if not filtered:
            label = QtWidgets.QLabel("This plugin does not expose extra options.")
            self.options_layout.addWidget(label)
            self.options_layout.addStretch(1)
            return

        for opt in filtered:
            row = QtWidgets.QFrame()
            row.setObjectName("optionRow")
            row_layout = QtWidgets.QVBoxLayout(row)
            row_layout.setContentsMargins(6, 6, 6, 6)
            row_layout.setSpacing(4)

            top = QtWidgets.QHBoxLayout()
            flag_text = opt.flags
            if opt.flag in required_flags or not opt.optional:
                flag_text = f"{flag_text}  [required]"
            flag_label = QtWidgets.QLabel(flag_text)
            flag_label.setMinimumWidth(270)
            top.addWidget(flag_label, 0)

            if opt.takes_value:
                if opt.value_kind == "choice" and opt.choices:
                    chooser = QtWidgets.QComboBox()
                    if opt.optional:
                        chooser.addItem("")
                    chooser.addItems(opt.choices)
                    chooser.currentTextChanged.connect(self._update_command_preview)
                    top.addWidget(chooser, 1)
                    control_widget = chooser
                else:
                    editor = QtWidgets.QLineEdit()
                    if opt.value_kind == "int":
                        validator = QtGui.QRegularExpressionValidator(
                            QtCore.QRegularExpression(r"^-?(0x[0-9A-Fa-f]+|\d+)$"),
                            editor,
                        )
                        editor.setValidator(validator)
                        editor.setPlaceholderText("integer (e.g. 10, 0x10)")
                    elif opt.value_kind == "int_list":
                        editor.setPlaceholderText("list of integers, quote values when needed")
                    elif opt.multi_value:
                        editor.setPlaceholderText("list input, quote values containing spaces")
                    elif opt.value_kind == "uri":
                        editor.setPlaceholderText("URI or local path")
                    else:
                        editor.setPlaceholderText("value")
                    editor.textChanged.connect(self._update_command_preview)
                    top.addWidget(editor, 1)
                    if opt.path_like:
                        browse = QtWidgets.QPushButton("...")
                        browse.setFixedWidth(34)
                        browse.clicked.connect(lambda _, e=editor, o=opt: self._pick_option_path(e, o))
                        top.addWidget(browse, 0)
                    control_widget = editor
            else:
                checkbox = QtWidgets.QCheckBox("Enable")
                checkbox.stateChanged.connect(self._update_command_preview)
                top.addWidget(checkbox, 0)
                top.addStretch(1)
                control_widget = checkbox

            row_layout.addLayout(top)
            desc_text = opt.description or "-"
            if opt.value_kind == "choice" and opt.choices:
                desc_text = f"{desc_text}\nChoices: {', '.join(opt.choices)}"
            elif opt.value_kind == "int_list":
                desc_text = f"{desc_text}\nInput format: integer list (supports 0x...)"
            desc = QtWidgets.QLabel(desc_text)
            desc.setWordWrap(True)
            desc.setStyleSheet("color: #637588;")
            row_layout.addWidget(desc)

            self.options_layout.addWidget(row)
            self.option_controls.append((opt, control_widget))

        self.options_layout.addStretch(1)

    def _pick_option_path(self, editor: QtWidgets.QLineEdit, option: Optional[PluginOption] = None) -> None:
        if option and option.dir_like:
            selected = QtWidgets.QFileDialog.getExistingDirectory(
                self,
                "Select directory",
                str(self.root_dir),
            )
            if selected:
                editor.setText(selected)
            return

        selected, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select file",
            str(self.root_dir),
            "All files (*.*)",
        )
        if selected:
            editor.setText(selected)

    def _choose_memory_file(self) -> None:
        selected, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select memory file", str(self.root_dir), "All files (*.*)"
        )
        if selected:
            self.memory_edit.setText(selected)
            self._push_recent_file(selected)

    def _on_recent_selected(self, value: str) -> None:
        if value:
            self.memory_edit.setText(value)

    def _push_recent_file(self, path: str) -> None:
        normalized = os.path.normpath(path)
        self.recent_files = [item for item in self.recent_files if os.path.normpath(item) != normalized]
        self.recent_files.insert(0, path)
        self.recent_files = self.recent_files[:RECENT_LIMIT]
        self.recent_combo.blockSignals(True)
        self.recent_combo.clear()
        self.recent_combo.addItems(self.recent_files)
        self.recent_combo.setCurrentText(path)
        self.recent_combo.blockSignals(False)
        self._save_state()

    def _current_mode(self) -> str:
        mode = self.mode_combo.currentText().strip()
        return mode if mode in MODE_TO_RENDERER else MODE_CLI

    def _on_mode_changed(self, _mode: str) -> None:
        is_analysis = self._current_mode() == MODE_ANALYSIS
        if is_analysis:
            self.result_stack.setCurrentIndex(0)  # table
        else:
            self.result_stack.setCurrentIndex(1)  # cli text
        self.result_search.setEnabled(is_analysis)
        if is_analysis:
            self.result_search.setPlaceholderText("Type to filter all table columns...")
        else:
            self.result_search.clear()
            self.result_search.setPlaceholderText("Result search is available in Analysis mode.")
            self.table_proxy.setFilterRegularExpression(QtCore.QRegularExpression())
            if self.loaded_row_count:
                self.result_count_label.setText(f"Rows: {self.loaded_row_count} (CLI mode)")
            else:
                self.result_count_label.setText("Rows: N/A (CLI mode)")
        self._update_command_preview()

    @staticmethod
    def _split_multi_value(raw: str) -> List[str]:
        text = raw.strip()
        if not text:
            return []
        try:
            tokens = shlex.split(text)
        except ValueError:
            tokens = []

        if not tokens:
            if "," in text:
                tokens = [piece.strip() for piece in text.split(",")]
            else:
                tokens = text.split()
        return [token for token in tokens if token]

    def _read_option_value(self, option: PluginOption, widget: QtWidgets.QWidget, strict: bool) -> Any:
        if isinstance(widget, QtWidgets.QCheckBox):
            return True if widget.isChecked() else None

        if isinstance(widget, QtWidgets.QComboBox):
            text = widget.currentText().strip()
            return text or None

        if isinstance(widget, QtWidgets.QLineEdit):
            text = widget.text().strip()
            if not text:
                return None

            if option.value_kind == "int":
                try:
                    return int(text, 0)
                except ValueError:
                    if strict:
                        raise ValueError(f"{option.flag} expects an integer (supports 0x...).")
                    return None

            if option.multi_value:
                pieces = self._split_multi_value(text)
                if option.value_kind == "int_list":
                    converted = []
                    for token in pieces:
                        try:
                            converted.append(int(token, 0))
                        except ValueError:
                            if strict:
                                raise ValueError(f"{option.flag} contains invalid integer: {token}")
                            return None
                    return converted
                return pieces

            return text

        return None

    def _collect_global_settings(self) -> Dict[str, Any]:
        return {
            "parallelism": self.parallel_combo.currentText().strip().lower(),
            "quiet": self.quiet_check.isChecked(),
            "offline": self.offline_check.isChecked(),
            "clear_cache": self.clear_cache_check.isChecked(),
            "plugin_dirs": self.plugin_dirs_edit.text().strip(),
            "symbol_dirs": self.symbol_dirs_edit.text().strip(),
            "single_location": self.single_location_edit.text().strip(),
            "stackers": self._split_multi_value(self.stackers_edit.text()),
            "cache_path": self.cache_path_edit.text().strip(),
        }

    def _collect_plugin_values(self, strict: bool) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        for option, widget in self.option_controls:
            value = self._read_option_value(option, widget, strict)
            if value is None:
                continue
            name = option.flag.lstrip("-").replace("-", "_")
            values[name] = value
        return values

    def _build_args(self, output_dir: Optional[Path] = None, strict: bool = False) -> List[str]:
        renderer = MODE_TO_RENDERER[self._current_mode()]
        out_dir = output_dir or (self.output_base / "preview")
        settings = self._collect_global_settings()
        args: List[str] = []

        parallelism = settings["parallelism"]
        if parallelism in ("threads", "processes"):
            args += ["--parallelism", parallelism]
        if settings["plugin_dirs"]:
            args += ["--plugin-dirs", settings["plugin_dirs"]]
        if settings["symbol_dirs"]:
            args += ["--symbol-dirs", settings["symbol_dirs"]]
        if settings["cache_path"]:
            args += ["--cache-path", settings["cache_path"]]
        if settings["offline"]:
            args.append("--offline")
        if settings["clear_cache"]:
            args.append("--clear-cache")
        if settings["quiet"]:
            args.append("-q")

        if renderer:
            args += ["-r", renderer]
        args += ["-o", str(out_dir)]

        memory_file = self.memory_edit.text().strip()
        if memory_file:
            args += ["-f", memory_file]
        if settings["single_location"]:
            args += ["--single-location", settings["single_location"]]
        if settings["stackers"]:
            args += ["--stackers", *settings["stackers"]]

        if self.selected_plugin:
            args.append(self.selected_plugin.name)

        for option, widget in self.option_controls:
            value = self._read_option_value(option, widget, strict)
            if value is None:
                continue

            if isinstance(widget, QtWidgets.QCheckBox):
                args.append(option.flag)
                continue

            args.append(option.flag)
            if isinstance(value, list):
                args.extend([str(piece) for piece in value])
            else:
                args.append(str(value))

        return args

    def _update_command_preview(self) -> None:
        try:
            command = [sys.executable, "vol.py", *self._build_args(strict=False)]
            self.command_preview.setText(subprocess.list2cmdline(command))
        except Exception as exc:
            self.command_preview.setText(f"(invalid option input) {exc}")

    def _run_analysis(self) -> None:
        if self.process and self.process.state() != QtCore.QProcess.NotRunning:
            QtWidgets.QMessageBox.warning(self, APP_TITLE, "Another command is already running.")
            return

        if not self.selected_plugin:
            QtWidgets.QMessageBox.warning(self, APP_TITLE, "Select a plugin first.")
            return

        memory = self.memory_edit.text().strip()
        if memory and not Path(memory).exists():
            QtWidgets.QMessageBox.critical(self, APP_TITLE, f"Memory file not found:\n{memory}")
            return

        try:
            plugin_values = self._collect_plugin_values(strict=True)
        except ValueError as exc:
            QtWidgets.QMessageBox.warning(self, APP_TITLE, f"Invalid option value:\n{exc}")
            return

        self._preflight_request_id += 1
        request_id = self._preflight_request_id
        plugin_name = self.selected_plugin.name
        settings = self._collect_global_settings()
        self.run_btn.setEnabled(False)
        self.status_label.setText(f"Preflight: {plugin_name}")

        self._start_async(
            func=lambda: self.catalog.preflight_unsatisfied(
                plugin_name=plugin_name,
                plugin_values=plugin_values,
                memory_file=memory,
                global_settings=settings,
            ),
            on_success=lambda payload, rid=request_id, pname=plugin_name, mem=memory: self._on_preflight_done(
                rid, pname, mem, payload
            ),
            on_error=lambda error, rid=request_id: self._on_preflight_error(rid, error),
        )

    def _on_preflight_done(self, request_id: int, plugin_name: str, memory: str, payload) -> None:
        if request_id != self._preflight_request_id:
            return
        self.run_btn.setEnabled(True)

        if not self.selected_plugin or self.selected_plugin.name != plugin_name:
            self.status_label.setText("Preflight canceled: selected plugin changed.")
            return

        preflight_issues, preflight_warning = payload
        if preflight_warning:
            self.status_label.setText(preflight_warning)
        if preflight_issues:
            sample = "\n".join(preflight_issues[:20])
            extra = "" if len(preflight_issues) <= 20 else f"\n... and {len(preflight_issues) - 20} more"
            QtWidgets.QMessageBox.warning(
                self,
                APP_TITLE,
                f"Unsatisfied requirements detected before run:\n\n{sample}{extra}",
            )
            return
        if not self.catalog.has_library_backend():
            missing_required = self._missing_required_flags()
            if missing_required:
                flags = ", ".join(missing_required)
                QtWidgets.QMessageBox.warning(
                    self,
                    APP_TITLE,
                    f"Required options are missing: {flags}\n\nCheck the plugin Usage section before running.",
                )
                return

        self._start_process(plugin_name=plugin_name, memory=memory)

    def _on_preflight_error(self, request_id: int, error: str) -> None:
        if request_id != self._preflight_request_id:
            return
        self.run_btn.setEnabled(True)
        self.status_label.setText(f"Preflight failed: {error}")

    def _start_process(self, plugin_name: str, memory: str) -> None:
        self.output_base.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        plugin_slug = plugin_name.replace(".", "_")
        output_dir = self.output_base / f"{stamp}_{plugin_slug}"
        output_dir.mkdir(parents=True, exist_ok=True)
        self.current_output_dir = output_dir
        self.run_mode = self._current_mode()
        self._run_serial += 1
        self._active_run_serial = self._run_serial

        try:
            args = self._build_args(output_dir=output_dir, strict=True)
        except ValueError as exc:
            QtWidgets.QMessageBox.warning(self, APP_TITLE, f"Invalid option value:\n{exc}")
            return
        self.current_command = [sys.executable, "vol.py", *args]
        self.command_preview.setText(subprocess.list2cmdline(self.current_command))

        self._close_stream_handles()
        self.stdout_preview = ""
        self.stderr_preview = ""
        self.stdout_stream_path = output_dir / "stdout.txt"
        self.stderr_stream_path = output_dir / "stderr.txt"
        try:
            self.stdout_stream_handle = self.stdout_stream_path.open("w", encoding="utf-8", errors="replace")
            self.stderr_stream_handle = self.stderr_stream_path.open("w", encoding="utf-8", errors="replace")
        except Exception as exc:
            QtWidgets.QMessageBox.critical(self, APP_TITLE, f"Failed to open output stream files:\n{exc}")
            self._close_stream_handles()
            return
        self.table_model.clear()
        self.cli_result_box.clear()
        self.analysis_raw_box.clear()
        self.loaded_row_count = 0
        self.log_box.clear()
        self.generated_files_list.clear()
        self.log_box.appendPlainText("Running command:")
        self.log_box.appendPlainText(subprocess.list2cmdline(self.current_command))
        self.log_box.appendPlainText("")

        self.run_started_at = time.time()
        self.process = QtCore.QProcess(self)
        self.process.setWorkingDirectory(str(self.root_dir))
        self.process.setProgram(sys.executable)
        self.process.setArguments(["vol.py", *args])
        self.process.readyReadStandardOutput.connect(self._on_stdout)
        self.process.readyReadStandardError.connect(self._on_stderr)
        self.process.finished.connect(self._on_finished)
        self.process.start()

        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_run_stage(RUN_STAGE_RUNNING)
        self.status_label.setText(f"Running: {plugin_name}")

        if memory:
            self._push_recent_file(memory)

    def _missing_required_flags(self) -> List[str]:
        if not self.selected_plugin:
            return []
        required = set(self.selected_plugin.required_flags)
        for option, _widget in self.option_controls:
            if not option.optional:
                required.add(option.flag)
        if not required:
            return []

        missing: List[str] = []
        for req in sorted(required):
            matched = [pair for pair in self.option_controls if pair[0].flag == req]
            if not matched:
                # If this required option was not rendered, still report it.
                missing.append(req)
                continue
            ok = False
            for _opt, widget in matched:
                if isinstance(widget, QtWidgets.QCheckBox):
                    ok = ok or widget.isChecked()
                elif isinstance(widget, QtWidgets.QLineEdit):
                    ok = ok or bool(widget.text().strip())
                elif isinstance(widget, QtWidgets.QComboBox):
                    ok = ok or bool(widget.currentText().strip())
            if not ok:
                missing.append(req)
        return missing

    def _stop_analysis(self) -> None:
        if not self.process or self.process.state() == QtCore.QProcess.NotRunning:
            return
        self.status_label.setText("Stopping process...")
        self.process.terminate()
        QtCore.QTimer.singleShot(2000, self._force_kill_if_needed)

    def _force_kill_if_needed(self) -> None:
        if self.process and self.process.state() != QtCore.QProcess.NotRunning:
            self.process.kill()

    def _close_stream_handles(self) -> None:
        for attr in ("stdout_stream_handle", "stderr_stream_handle"):
            handle = getattr(self, attr, None)
            if handle is None:
                continue
            try:
                handle.flush()
                handle.close()
            except Exception:
                pass
            setattr(self, attr, None)

    @staticmethod
    def _append_preview_chunk(current: str, chunk: str, limit: int = MAX_STREAM_PREVIEW_CHARS) -> str:
        if not chunk:
            return current
        if limit <= 0:
            return current + chunk
        remain = limit - len(current)
        if remain <= 0:
            return current
        if len(chunk) <= remain:
            return current + chunk
        return current + chunk[:remain]

    def _on_stdout(self) -> None:
        if not self.process:
            return
        chunk = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")
        if self.stdout_stream_handle is not None:
            try:
                self.stdout_stream_handle.write(chunk)
            except Exception:
                pass
        self.stdout_preview = self._append_preview_chunk(self.stdout_preview, chunk)
        if self.run_mode == MODE_CLI and chunk:
            cursor = self.cli_result_box.textCursor()
            cursor.movePosition(QtGui.QTextCursor.End)
            cursor.insertText(chunk)
            self.cli_result_box.setTextCursor(cursor)
            self.cli_result_box.ensureCursorVisible()
        elif self.run_mode == MODE_ANALYSIS and chunk:
            self.analysis_raw_box.moveCursor(QtGui.QTextCursor.End)
            self.analysis_raw_box.insertPlainText(chunk)
            self.analysis_raw_box.ensureCursorVisible()

    def _on_stderr(self) -> None:
        if not self.process:
            return
        chunk = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace")
        if self.stderr_stream_handle is not None:
            try:
                self.stderr_stream_handle.write(chunk)
            except Exception:
                pass
        self.stderr_preview = self._append_preview_chunk(self.stderr_preview, chunk)
        if chunk:
            self.log_box.moveCursor(QtGui.QTextCursor.End)
            self.log_box.insertPlainText(chunk)
            self.log_box.ensureCursorVisible()
    def _on_finished(self, exit_code: int, _status: QtCore.QProcess.ExitStatus) -> None:
        elapsed = time.time() - self.run_started_at
        self._close_stream_handles()
        run_serial = self._active_run_serial
        run_mode = self.run_mode
        output_dir = self.current_output_dir
        command = list(self.current_command)
        stdout_preview = self.stdout_preview
        stderr_preview = self.stderr_preview

        self.stop_btn.setEnabled(False)
        self.run_btn.setEnabled(False)

        if exit_code == 0:
            base_status = f"Success in {elapsed:.2f}s"
        else:
            base_status = f"Failed ({exit_code}) in {elapsed:.2f}s"
        self.status_label.setText(f"{base_status} | Post-processing...")

        self._start_async(
            func=lambda: self._postprocess_run_payload(
                run_mode=run_mode,
                output_dir=output_dir,
                command=command,
                exit_code=exit_code,
                elapsed=elapsed,
                stdout_preview=stdout_preview,
                stderr_preview=stderr_preview,
            ),
            on_success=lambda payload, serial=run_serial, status=base_status: self._on_run_postprocess_done(
                serial, status, payload
            ),
            on_error=lambda error, serial=run_serial, status=base_status, code=exit_code, sec=elapsed, out=stdout_preview, err=stderr_preview, mode=run_mode: self._on_run_postprocess_error(
                serial, status, code, sec, out, err, mode, error
            ),
        )

    def _postprocess_run_payload(
        self,
        run_mode: str,
        output_dir: Optional[Path],
        command: List[str],
        exit_code: int,
        elapsed: float,
        stdout_preview: str,
        stderr_preview: str,
    ) -> Dict[str, Any]:
        stdout_path = (output_dir / "stdout.txt") if output_dir else None
        stderr_path = (output_dir / "stderr.txt") if output_dir else None
        stdout_text = self._read_text_limited(
            stdout_path,
            MAX_CLI_UI_CHARS if run_mode == MODE_CLI else MAX_STREAM_PREVIEW_CHARS,
        )
        if not stdout_text:
            stdout_text = stdout_preview
        stderr_text = self._read_text_limited(stderr_path, MAX_STREAM_PREVIEW_CHARS)
        if not stderr_text:
            stderr_text = stderr_preview

        rows: List[dict] = []
        parse_note = ""
        if run_mode == MODE_ANALYSIS:
            rows, parse_note = self._load_rows_from_stdout_file(stdout_path)

        persist_error = self._persist_run_artifacts(
            run_mode=run_mode,
            output_dir=output_dir,
            command=command,
            exit_code=exit_code,
            elapsed=elapsed,
            stdout=stdout_text,
            stderr=stderr_text,
            rows=rows,
        )
        summary = self._result_summary(
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            run_mode=run_mode,
            analysis_rows=len(rows),
        )
        if parse_note:
            if not summary or summary == "No rows returned.":
                summary = parse_note
            else:
                summary = f"{summary} | {parse_note}"
        return {
            "run_mode": run_mode,
            "rows": rows,
            "exit_code": exit_code,
            "elapsed": elapsed,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "summary": summary,
            "persist_error": persist_error,
        }

    def _on_run_postprocess_done(self, run_serial: int, base_status: str, payload: Dict[str, Any]) -> None:
        if run_serial != self._active_run_serial:
            return

        run_mode = str(payload.get("run_mode", self.run_mode))
        rows = payload.get("rows", [])
        exit_code = int(payload.get("exit_code", 1))
        elapsed = float(payload.get("elapsed", 0.0))
        stdout = str(payload.get("stdout", ""))
        stderr = str(payload.get("stderr", ""))
        summary = str(payload.get("summary", "") or "")
        persist_error = payload.get("persist_error")

        if run_mode == MODE_ANALYSIS:
            self._set_result_table(rows if isinstance(rows, list) else [])
        else:
            self._set_cli_result(stdout)

        self._write_log(exit_code, elapsed, stdout, stderr, run_mode=run_mode)
        self._refresh_generated_files()

        status = base_status
        if summary:
            status = f"{status} | {summary}"
        if persist_error:
            status = f"{status} | save failed: {persist_error}"
        self.status_label.setText(status)
        self._set_run_stage(RUN_STAGE_DONE)
        self.run_btn.setEnabled(True)

    def _on_run_postprocess_error(
        self,
        run_serial: int,
        base_status: str,
        exit_code: int,
        elapsed: float,
        stdout: str,
        stderr: str,
        run_mode: str,
        error: str,
    ) -> None:
        if run_serial != self._active_run_serial:
            return

        if run_mode == MODE_ANALYSIS:
            self._set_result_table(self._rows_from_stdout_mode(run_mode, stdout))
        else:
            self._set_cli_result(stdout)
        self._write_log(exit_code, elapsed, stdout, stderr, run_mode=run_mode)
        summary = self._result_summary(exit_code, stdout, stderr, run_mode=run_mode)
        status = f"{base_status} | Post-process failed: {error}"
        if summary:
            status = f"{status} | {summary}"
        self.status_label.setText(status)
        self._set_run_stage(RUN_STAGE_DONE)
        self.run_btn.setEnabled(True)

    @staticmethod
    def _read_text_limited(path: Optional[Path], max_chars: int) -> str:
        if path is None:
            return ""
        if not path.exists():
            return ""
        if max_chars <= 0:
            try:
                return path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return ""
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fp:
                text = fp.read(max_chars + 1)
        except Exception:
            return ""
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n... (truncated for UI)"

    def _load_rows_from_stdout_file(self, stdout_path: Optional[Path]) -> Tuple[List[dict], str]:
        if stdout_path is None or not stdout_path.exists():
            return [], "stdout.txt missing; table parsing skipped."
        try:
            size = stdout_path.stat().st_size
        except Exception as exc:
            return [], f"stdout size check failed: {exc}"

        if size > MAX_ANALYSIS_PARSE_BYTES:
            return (
                [],
                f"Analysis output too large ({size} bytes). Table parsing skipped; check result.csv/result.txt.",
            )

        try:
            stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return [], f"Failed to read stdout for table parsing: {exc}"

        payload = self._extract_json_payload(stdout_text)
        if payload is None:
            return [], "JSON payload not found in stdout."

        rows = self._flatten_rows(payload, max_rows=MAX_ANALYSIS_PARSE_ROWS)
        if len(rows) >= MAX_ANALYSIS_PARSE_ROWS:
            return rows, f"Rows truncated at {MAX_ANALYSIS_PARSE_ROWS} during parse."
        return rows, ""

    def _rows_from_stdout(self, stdout: str) -> List[dict]:
        return self._rows_from_stdout_mode(self.run_mode, stdout)

    def _rows_from_stdout_mode(self, run_mode: str, stdout: str) -> List[dict]:
        if run_mode != MODE_ANALYSIS:
            return []
        payload = self._extract_json_payload(stdout)
        if payload is None:
            return []
        return self._flatten_rows(payload, max_rows=MAX_ANALYSIS_PARSE_ROWS)

    def _set_result_table(self, rows: List[dict]) -> None:
        self.table_model.clear()
        if self.run_mode == MODE_ANALYSIS:
            self.result_search.clear()

        if not rows:
            self.loaded_row_count = 0
            if self.run_mode == MODE_ANALYSIS:
                self.result_count_label.setText("Rows: 0")
            else:
                self.result_count_label.setText("Rows: N/A (CLI mode)")
            return

        columns = list(rows[0].keys())
        seen = set(columns)
        for row in rows[1:]:
            for key in row.keys():
                if key not in seen:
                    seen.add(key)
                    columns.append(key)
        columns = self._ordered_columns(columns)

        self.table_model.setHorizontalHeaderLabels(columns)
        root_item = self.table_model.invisibleRootItem()
        parent_by_depth: Dict[int, QtGui.QStandardItem] = {0: root_item}
        for row in rows[:MAX_TABLE_ROWS]:
            depth_value = row.get("_depth", 0)
            depth = int(depth_value) if isinstance(depth_value, int) and depth_value >= 0 else 0
            items = []
            for column in columns:
                value = row.get(column, "")
                text = self._to_text(value)
                item = QtGui.QStandardItem(text)
                item.setEditable(False)
                if isinstance(value, (int, float)):
                    item.setData(value, QtCore.Qt.UserRole)
                else:
                    item.setData(text.lower(), QtCore.Qt.UserRole)
                items.append(item)
            parent = parent_by_depth.get(depth, root_item)
            if isinstance(parent, QtGui.QStandardItem):
                parent.appendRow(items)
            else:
                root_item.appendRow(items)
            parent_by_depth[depth + 1] = items[0]
            for stale_depth in [key for key in parent_by_depth if key > depth + 1]:
                del parent_by_depth[stale_depth]

        shown = min(len(rows), MAX_TABLE_ROWS)
        self.loaded_row_count = shown
        suffix = "" if shown == len(rows) else f" (clipped from {len(rows)})"
        if self.run_mode == MODE_ANALYSIS:
            self.result_count_label.setText(f"Rows: {shown}{suffix}")
        else:
            self.result_count_label.setText(f"Rows: {shown} (CLI mode)")
        for column_index in range(len(columns)):
            self.table_view.resizeColumnToContents(column_index)

    def _set_cli_result(self, stdout: str) -> None:
        text = stdout
        if not text:
            text = "(empty)"
        self.cli_result_box.setPlainText(text)
        line_count = len(text.splitlines()) if text else 0
        self.result_count_label.setText(f"Lines: {line_count} (CLI mode)")

    def _ordered_columns(self, columns: List[str]) -> List[str]:
        priority_index = {name: idx for idx, name in enumerate(COLUMN_PRIORITY)}

        def rank(col: str) -> Tuple[int, int]:
            if col.startswith("_"):
                return (2000, 0)
            if col in priority_index:
                return (priority_index[col], 0)
            return (1000, 0)

        # Stable ordering: priority first, metadata last, original order preserved for ties.
        indexed = list(enumerate(columns))
        indexed.sort(key=lambda item: (rank(item[1])[0], item[0]))
        return [col for _, col in indexed]

    def _write_log(
        self,
        exit_code: int,
        elapsed: float,
        stdout: str,
        stderr: str,
        run_mode: Optional[str] = None,
    ) -> None:
        mode = run_mode or self.run_mode
        self.log_box.clear()
        renderer_label = MODE_TO_RENDERER[mode] or "default(quick)"
        self.log_box.appendPlainText("Command:")
        self.log_box.appendPlainText(subprocess.list2cmdline(self.current_command))
        self.log_box.appendPlainText(f"Mode: {mode} ({renderer_label})")
        self.log_box.appendPlainText("")
        self.log_box.appendPlainText(f"Exit code: {exit_code}")
        self.log_box.appendPlainText(f"Elapsed: {elapsed:.2f}s")
        if self.current_output_dir:
            self.log_box.appendPlainText(f"Output dir: {self.current_output_dir}")
            self.log_box.appendPlainText(
                "Saved: command.txt, stdout.txt, stderr.txt, run_meta.json, result.json, result.csv, result.txt"
            )
        self.log_box.appendPlainText("")
        self.log_box.appendPlainText("STDERR")
        self.log_box.appendPlainText(stderr if stderr.strip() else "(empty)")
        self.log_box.appendPlainText("")
        if mode == MODE_CLI:
            self.log_box.appendPlainText("STDOUT (CLI)")
            output = stdout if stdout else "(empty)"
            self.log_box.appendPlainText(output)
        else:
            self.log_box.appendPlainText("STDOUT (preview)")
            preview = stdout[:4000]
            if not preview.strip():
                preview = "(empty)"
            self.log_box.appendPlainText(preview)
            if len(stdout) > len(preview):
                self.log_box.appendPlainText("\n... (truncated)")

    def _result_summary(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
        run_mode: Optional[str] = None,
        analysis_rows: Optional[int] = None,
    ) -> str:
        mode = run_mode or self.run_mode
        if exit_code != 0:
            line = self._first_issue_line(stderr, stdout)
            return line or "Execution failed."

        rows = 0
        if mode == MODE_ANALYSIS:
            if analysis_rows is not None:
                rows = analysis_rows
            else:
                payload = self._extract_json_payload(stdout)
                if isinstance(payload, list):
                    rows = len(payload)
                elif payload is not None:
                    rows = 1
            if rows == 0:
                line = self._first_issue_line(stderr, "")
                return line or "No rows returned."

        line = self._first_issue_line(stderr, "")
        if line:
            return line
        return ""

    def _first_issue_line(self, stderr: str, stdout: str) -> str:
        joined = "\n".join([stderr or "", stdout or ""])
        for line in joined.splitlines():
            s = line.strip()
            if not s:
                continue
            up = s.upper()
            if "WARNING" in up or "ERROR" in up or "UNSATISFIED REQUIREMENT" in up:
                return s[:180]
        for line in joined.splitlines():
            s = line.strip()
            if s and "Volatility 3 Framework" not in s:
                return s[:180]
        return ""

    def _persist_run_artifacts(
        self,
        run_mode: str,
        output_dir: Optional[Path],
        command: List[str],
        exit_code: int,
        elapsed: float,
        stdout: str,
        stderr: str,
        rows: Optional[List[dict]] = None,
    ) -> Optional[str]:
        if not output_dir:
            return None
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "command.txt").write_text(
                subprocess.list2cmdline(command) + "\n",
                encoding="utf-8",
            )
            stdout_path = output_dir / "stdout.txt"
            stderr_path = output_dir / "stderr.txt"
            if not stdout_path.exists():
                stdout_path.write_text(stdout, encoding="utf-8")
            if not stderr_path.exists():
                stderr_path.write_text(stderr, encoding="utf-8")
            renderer_label = MODE_TO_RENDERER[run_mode] or "default(quick)"
            meta = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "mode": run_mode,
                "renderer": renderer_label,
                "exit_code": exit_code,
                "elapsed_seconds": round(elapsed, 3),
                "command": command,
                "output_dir": str(output_dir),
            }
            (output_dir / "run_meta.json").write_text(
                json.dumps(meta, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            export_rows = rows if isinstance(rows, list) else []
            result_json, csv_columns, csv_rows, text_view = self._build_export_payloads(
                run_mode=run_mode,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                export_rows=export_rows,
            )
            (output_dir / "result.json").write_text(
                json.dumps(result_json, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self._write_csv_file(output_dir / "result.csv", csv_columns, csv_rows)
            (output_dir / "result.txt").write_text(text_view, encoding="utf-8")
            return None
        except Exception as exc:
            return str(exc)

    def _persist_run_files(self, exit_code: int, elapsed: float, stdout: str, stderr: str) -> None:
        error = self._persist_run_artifacts(
            run_mode=self.run_mode,
            output_dir=self.current_output_dir,
            command=self.current_command,
            exit_code=exit_code,
            elapsed=elapsed,
            stdout=stdout,
            stderr=stderr,
        )
        self._refresh_generated_files()
        if error:
            self.status_label.setText(f"Run completed, but save failed: {error}")
            return

    def _apply_result_filter(self, text: str) -> None:
        if self._current_mode() != MODE_ANALYSIS:
            return
        escaped = re.escape(text.strip())
        regex = QtCore.QRegularExpression(
            escaped, QtCore.QRegularExpression.CaseInsensitiveOption
        )
        self.table_proxy.setFilterRegularExpression(regex)
        filtered = self.table_proxy.rowCount()
        if self.loaded_row_count:
            self.result_count_label.setText(f"Rows: {filtered}/{self.loaded_row_count}")
        else:
            self.result_count_label.setText("Rows: 0")

    def _extract_json_payload(self, text: str):
        decoder = json.JSONDecoder()
        best_payload = None
        best_consumed = -1
        for index, ch in enumerate(text):
            if ch not in "[{":
                continue
            try:
                payload, consumed = decoder.raw_decode(text[index:])
                if consumed > best_consumed:
                    best_payload = payload
                    best_consumed = consumed
                remainder = text[index + consumed :].strip()
                if not remainder:
                    return payload
            except json.JSONDecodeError:
                continue
        return best_payload

    def _flatten_rows(self, payload, max_rows: Optional[int] = None) -> List[dict]:
        rows: List[dict] = []

        def walk(node, depth: int = 0, parent: str = "") -> None:
            if max_rows is not None and len(rows) >= max_rows:
                return
            if isinstance(node, list):
                for child in node:
                    if max_rows is not None and len(rows) >= max_rows:
                        break
                    walk(child, depth, parent)
                return
            if isinstance(node, dict):
                row = {key: value for key, value in node.items() if key != "__children"}
                children = node.get("__children")
                if depth:
                    row["_depth"] = depth
                if parent:
                    row["_parent"] = parent
                if isinstance(children, list):
                    row["_child_count"] = len(children)
                if row:
                    rows.append(row)
                if isinstance(children, list):
                    parent_token = str(node.get("Data", parent))
                    for child in children:
                        if max_rows is not None and len(rows) >= max_rows:
                            break
                        walk(child, depth + 1, parent_token)
                return
            if max_rows is None or len(rows) < max_rows:
                rows.append({"value": node, "_depth": depth, "_parent": parent})

        walk(payload)
        return rows

    @staticmethod
    def _to_text(value) -> str:
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _compact_text_cell(text: str, max_len: int = MAX_EXPORT_TEXT_WIDTH) -> str:
        clean = text.replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
        if len(clean) <= max_len:
            return clean
        return clean[: max_len - 3] + "..."

    def _columns_from_rows(self, rows: List[dict]) -> List[str]:
        columns: List[str] = []
        seen = set()
        for row in rows:
            for key in row.keys():
                if key in seen:
                    continue
                seen.add(key)
                columns.append(key)
        if not columns:
            columns = ["value"]
        return self._ordered_columns(columns)

    def _rows_to_text_table(self, columns: List[str], rows: List[dict]) -> str:
        if not rows:
            return "(no rows)\n"
        limited = rows[:MAX_EXPORT_TXT_ROWS]
        widths: Dict[str, int] = {}
        for column in columns:
            widths[column] = min(MAX_EXPORT_TEXT_WIDTH, len(column))
        for row in limited:
            for column in columns:
                value = self._compact_text_cell(self._to_text(row.get(column, "")))
                widths[column] = min(MAX_EXPORT_TEXT_WIDTH, max(widths[column], len(value)))

        header = " | ".join(column.ljust(widths[column]) for column in columns)
        bar = "-+-".join("-" * widths[column] for column in columns)
        lines = [header, bar]
        for row in limited:
            line = " | ".join(
                self._compact_text_cell(self._to_text(row.get(column, ""))).ljust(widths[column])
                for column in columns
            )
            lines.append(line)
        if len(rows) > len(limited):
            lines.append(f"... ({len(rows) - len(limited)} more rows)")
        return "\n".join(lines) + "\n"

    def _write_csv_file(self, path: Path, columns: List[str], rows: List[dict]) -> None:
        with path.open("w", encoding="utf-8-sig", newline="") as fp:
            writer = csv.writer(fp)
            writer.writerow(columns)
            for row in rows:
                writer.writerow([self._to_text(row.get(column, "")) for column in columns])

    def _build_export_payloads(
        self,
        run_mode: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        export_rows: List[dict],
    ) -> Tuple[Any, List[str], List[dict], str]:
        if run_mode == MODE_ANALYSIS:
            if export_rows:
                columns = self._columns_from_rows(export_rows)
                result_json = export_rows
                text_view = self._rows_to_text_table(columns, export_rows)
                return result_json, columns, export_rows, text_view

            stdout_lines = stdout.splitlines()
            stderr_lines = stderr.splitlines()
            csv_rows: List[dict] = []
            for idx, line in enumerate(stdout_lines, 1):
                csv_rows.append({"source": "stdout", "line_no": idx, "text": line})
            for idx, line in enumerate(stderr_lines, 1):
                csv_rows.append({"source": "stderr", "line_no": idx, "text": line})
            columns = ["source", "line_no", "text"]
            result_json = {
                "mode": run_mode,
                "exit_code": exit_code,
                "row_count": 0,
                "fallback": "raw_lines",
                "stdout_line_count": len(stdout_lines),
                "stderr_line_count": len(stderr_lines),
                "stdout": stdout,
                "stderr": stderr,
            }
            if stdout.strip():
                text_view = stdout
            elif stderr.strip():
                text_view = stderr
            else:
                text_view = "(empty)\n"
            return result_json, columns, csv_rows, text_view

        lines = stdout.splitlines()
        csv_rows = [{"line_no": idx + 1, "text": line} for idx, line in enumerate(lines)]
        columns = ["line_no", "text"]
        result_json = {
            "mode": run_mode,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "line_count": len(lines),
        }
        text_view = stdout if stdout.strip() else "(empty)\n"
        return result_json, columns, csv_rows, text_view

    def _refresh_generated_files(self) -> None:
        self.generated_files_list.clear()
        if not self.current_output_dir or not self.current_output_dir.exists():
            return
        excluded = {"command.txt", "stdout.txt", "stderr.txt", "run_meta.json"}
        files = sorted(
            [path for path in self.current_output_dir.rglob("*") if path.is_file()],
            key=lambda item: str(item.relative_to(self.current_output_dir)).lower(),
        )
        for path in files:
            rel = path.relative_to(self.current_output_dir)
            if rel.parent == Path(".") and path.name in excluded:
                continue
            size = path.stat().st_size
            item = QtWidgets.QListWidgetItem(f"{rel} ({size} bytes)")
            item.setData(QtCore.Qt.UserRole, str(path))
            self.generated_files_list.addItem(item)

    def _open_path(self, path: Path) -> None:
        if sys.platform.startswith("win"):
            os.startfile(str(path))
            return
        if sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
            return
        subprocess.run(["xdg-open", str(path)], check=False)

    def _open_selected_generated_file(self, _item: Optional[QtWidgets.QListWidgetItem] = None) -> None:
        current = self.generated_files_list.currentItem()
        if not current:
            return
        path = Path(str(current.data(QtCore.Qt.UserRole)))
        if not path.exists():
            QtWidgets.QMessageBox.warning(self, APP_TITLE, f"File not found:\n{path}")
            return
        try:
            self._open_path(path)
        except Exception as exc:
            QtWidgets.QMessageBox.critical(self, APP_TITLE, f"Failed to open file:\n{exc}")

    def _open_output_dir(self) -> None:
        target = self.current_output_dir or self.output_base
        target.mkdir(parents=True, exist_ok=True)
        try:
            self._open_path(target)
        except Exception as exc:
            QtWidgets.QMessageBox.critical(self, APP_TITLE, f"Failed to open output folder:\n{exc}")

    def _load_state(self) -> None:
        if not self.state_path.exists():
            return
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return

        recent = [str(item) for item in state.get("recent_files", []) if str(item).strip()]
        self.recent_files = recent[:RECENT_LIMIT]
        self.recent_combo.clear()
        self.recent_combo.addItems(self.recent_files)

        last_memory = str(state.get("last_memory_file", "")).strip()
        if last_memory:
            self.memory_edit.setText(last_memory)

        mode = str(state.get("mode", MODE_CLI)).strip()
        if mode not in MODE_TO_RENDERER:
            mode = MODE_CLI
        self.mode_combo.setCurrentText(mode)

        show_deprecated = bool(state.get("show_deprecated", False))
        self.show_deprecated_check.setChecked(show_deprecated)

        self.quiet_check.setChecked(bool(state.get("quiet", False)))
        parallelism = str(state.get("parallelism", "off")).strip().lower()
        if parallelism not in ("off", "threads", "processes"):
            parallelism = "off"
        self.parallel_combo.setCurrentText(parallelism)
        self.offline_check.setChecked(bool(state.get("offline", False)))
        self.clear_cache_check.setChecked(bool(state.get("clear_cache", False)))
        self.plugin_dirs_edit.setText(str(state.get("plugin_dirs", "")).strip())
        self.symbol_dirs_edit.setText(str(state.get("symbol_dirs", "")).strip())
        self.single_location_edit.setText(str(state.get("single_location", "")).strip())
        stackers = state.get("stackers", [])
        if isinstance(stackers, list):
            self.stackers_edit.setText(" ".join([str(item) for item in stackers if str(item).strip()]))
        self.cache_path_edit.setText(str(state.get("cache_path", "")).strip())
        self._update_plugin_dir_warning()

    def _save_state(self) -> None:
        payload = {
            "recent_files": self.recent_files[:RECENT_LIMIT],
            "last_memory_file": self.memory_edit.text().strip(),
            "mode": self._current_mode(),
            "show_deprecated": self.show_deprecated_check.isChecked(),
            "quiet": self.quiet_check.isChecked(),
            "parallelism": self.parallel_combo.currentText().strip().lower(),
            "offline": self.offline_check.isChecked(),
            "clear_cache": self.clear_cache_check.isChecked(),
            "plugin_dirs": self.plugin_dirs_edit.text().strip(),
            "symbol_dirs": self.symbol_dirs_edit.text().strip(),
            "single_location": self.single_location_edit.text().strip(),
            "stackers": self._split_multi_value(self.stackers_edit.text()),
            "cache_path": self.cache_path_edit.text().strip(),
            "saved_at": datetime.now().isoformat(timespec="seconds"),
        }
        try:
            self.state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:  # noqa: N802
        if self.process and self.process.state() != QtCore.QProcess.NotRunning:
            result = QtWidgets.QMessageBox.question(
                self,
                APP_TITLE,
                "A command is still running. Exit anyway?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No,
            )
            if result != QtWidgets.QMessageBox.Yes:
                event.ignore()
                return
            self.process.kill()
        self._close_stream_handles()
        for thread in list(self._active_threads):
            thread.quit()
            thread.wait(250)
        self._active_threads.clear()
        self._async_jobs.clear()
        self._save_state()
        super().closeEvent(event)


def main() -> None:
    root_dir = Path(__file__).resolve().parent
    if not (root_dir / "vol.py").exists():
        raise SystemExit("vol.py not found. Keep this script in the volatility3 root directory.")

    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    window = VolGuiWindow(root_dir)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
