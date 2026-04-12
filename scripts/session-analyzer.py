#!/usr/bin/env python3
"""
Session Analyzer for Claude Code

Parses Claude Code session JSONL files and outputs structured usage metrics as JSON.

Usage:
  python3 scripts/session-analyzer.py --project /path/to/project
  python3 scripts/session-analyzer.py --all
  python3 scripts/session-analyzer.py --global
"""

import json
import os
import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Dict, List, Any, Optional, Set, Tuple
import re


class SessionAnalyzer:
    """Parses Claude Code session JSONL files and generates usage metrics."""

    # Whitelisted Agent parameters
    AGENT_WHITELIST = {
        'subagent_type', 'name', 'model', 'isolation',
        'run_in_background', 'mode'
    }

    # Skill tool whitelisted params
    SKILL_WHITELIST = {'skill', 'args'}

    # Secret pattern for redaction
    SECRET_PATTERN = re.compile(
        r'(key|secret|token|password|credential|api_key|auth)',
        re.IGNORECASE
    )

    def __init__(self):
        """Initialize analyzer state."""
        self.tools_used = defaultdict(int)
        self.skills_used = defaultdict(int)
        self.agents_created = []
        self.features = {
            'git_worktrees': False,
            'agent_teams': False,
            'named_subagents': False,
            'background_agents': False,
            'model_alias_override': False,
            'skills_system': False,
            'task_create_update': False,
            'web_fetch_search': False,
            'browser_automation': False,
            'mcp_servers': False,
            'plan_subagent': False,
            'explore_subagent': False,
            'monitor_tool': False,
        }
        self.message_counts = {'user': 0, 'assistant': 0}
        self.timestamps = []
        self.weekly_stats = defaultdict(lambda: {'sessions': 0, 'tools': 0})

    @staticmethod
    def resolve_project_path(project_hash: str) -> str:
        """Convert project hash to actual path.

        Example: -Users-foo-bar -> /Users/foo/bar
        """
        if not project_hash.startswith('-'):
            return project_hash

        # Remove leading dash and replace dashes with slashes
        parts = project_hash[1:].split('-')
        return '/' + '/'.join(parts)

    @staticmethod
    def redact_sensitive_value(key: str, value: Any) -> Any:
        """Redact value if key matches secret pattern."""
        if not isinstance(key, str) or not isinstance(value, str):
            return value

        if SessionAnalyzer.SECRET_PATTERN.search(key):
            return f"<redacted:{len(value)} chars>"

        return value

    def extract_agent_call(self, tool_input: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract whitelisted Agent parameters."""
        extracted = {}
        for key, value in tool_input.items():
            if key in self.AGENT_WHITELIST:
                extracted[key] = self.redact_sensitive_value(key, value)

        return extracted if extracted else None

    def extract_skill_call(self, tool_input: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract whitelisted Skill parameters."""
        extracted = {}

        if 'skill' in tool_input:
            extracted['skill'] = tool_input['skill']

        if 'args' in tool_input:
            args = tool_input['args']
            if isinstance(args, dict):
                extracted['args'] = {
                    k: self.redact_sensitive_value(k, v)
                    for k, v in args.items()
                }
            else:
                extracted['args'] = args

        return extracted if extracted else None

    def process_tool_use(self, tool_use: Dict[str, Any]) -> None:
        """Process a single tool_use block."""
        tool_name = tool_use.get('name', 'unknown')
        self.tools_used[tool_name] += 1

        tool_input = tool_use.get('input', {})
        if not isinstance(tool_input, dict):
            return

        # Detect features based on tool calls
        if tool_name == 'Agent':
            extracted = self.extract_agent_call(tool_input)
            if extracted:
                self.agents_created.append(extracted)

            subtype = tool_input.get('subagent_type')
            if subtype == 'Plan':
                self.features['plan_subagent'] = True
            elif subtype == 'Explore':
                self.features['explore_subagent'] = True

            if tool_input.get('name'):
                self.features['named_subagents'] = True
            if tool_input.get('run_in_background'):
                self.features['background_agents'] = True
            if tool_input.get('model'):
                self.features['model_alias_override'] = True
            if tool_input.get('isolation') == 'worktree':
                self.features['git_worktrees'] = True

        elif tool_name == 'TeamCreate':
            self.features['agent_teams'] = True

        elif tool_name == 'Skill':
            extracted = self.extract_skill_call(tool_input)
            if extracted and 'skill' in extracted:
                self.skills_used[extracted['skill']] += 1
            self.features['skills_system'] = True

        elif tool_name in ('TaskCreate', 'TaskUpdate'):
            self.features['task_create_update'] = True

        elif tool_name in ('WebFetch', 'WebSearch'):
            self.features['web_fetch_search'] = True

        elif tool_name == 'Monitor':
            self.features['monitor_tool'] = True

        elif tool_name.startswith('mcp__claude-in-chrome__'):
            self.features['browser_automation'] = True
            self.features['mcp_servers'] = True

        elif tool_name.startswith('mcp__'):
            self.features['mcp_servers'] = True

    def process_message(self, msg: Dict[str, Any]) -> None:
        """Process a single message from JSONL."""
        msg_type = msg.get('type')

        if msg_type == 'user':
            self.message_counts['user'] += 1
        elif msg_type == 'assistant':
            self.message_counts['assistant'] += 1
            message_data = msg.get('message', {})
            if isinstance(message_data, dict):
                content = message_data.get('content', [])
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get('type') == 'tool_use':
                            self.process_tool_use(block)

        # Track timestamp for weekly analysis
        if 'timestamp' in msg:
            self.timestamps.append(msg['timestamp'])

    def parse_jsonl_file(self, filepath: str) -> int:
        """Parse JSONL file and return count of valid messages."""
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        msg = json.loads(line)
                        self.process_message(msg)
                        count += 1
                    except json.JSONDecodeError:
                        pass  # Skip malformed lines
        except (IOError, OSError) as e:
            pass  # Skip unreadable files

        return count

    def analyze_project(self, project_path: str) -> Tuple[Dict[str, Any], bool]:
        """Analyze a single project directory.

        Returns: (metrics_dict, has_sessions)
        """
        # Reset state for this project
        self.__init__()

        project_dir = Path(project_path)
        if not project_dir.exists():
            return {}, False

        # Find all JSONL files
        jsonl_files = list(project_dir.glob('**/*.jsonl'))
        if not jsonl_files:
            return {}, False

        messages_parsed = 0
        for jsonl_file in jsonl_files:
            messages_parsed += self.parse_jsonl_file(str(jsonl_file))

        if messages_parsed == 0:
            return {}, False

        # Build metrics
        metrics = {
            'has_sessions': True,
            'jsonl_files': len(jsonl_files),
            'messages_parsed': messages_parsed,
            'message_counts': dict(self.message_counts),
            'tools': self._build_tools_dict(),
            'skills_used': dict(self.skills_used),
            'agent_patterns': {
                'total_agents_created': len(self.agents_created),
                'agents': self.agents_created[:100],  # Limit to 100
            },
            'features_detected': self.features,
            'temporal': self._build_temporal_stats(),
        }

        return metrics, True

    def _build_tools_dict(self) -> Dict[str, Any]:
        """Build tools dictionary with counts and percentages."""
        total = sum(self.tools_used.values())
        if total == 0:
            return {'count': 0, 'by_name': {}}

        by_name = {}
        for tool_name in sorted(self.tools_used.keys(),
                               key=lambda x: self.tools_used[x], reverse=True):
            count = self.tools_used[tool_name]
            by_name[tool_name] = {
                'count': count,
                'percentage': round(100 * count / total, 1)
            }

        return {
            'total': total,
            'unique_tools': len(self.tools_used),
            'by_name': by_name
        }

    def _build_temporal_stats(self) -> Dict[str, Any]:
        """Build weekly session and tool call statistics."""
        if not self.timestamps:
            return {'weeks': {}}

        weeks = defaultdict(lambda: {'sessions': 0, 'tools': 0})
        for timestamp_str in self.timestamps:
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                week_start = dt - timedelta(days=dt.weekday())
                week_key = week_start.strftime('%Y-W%U')
                weeks[week_key]['sessions'] += 1
            except ValueError:
                pass

        return {'weeks': dict(weeks)}

    def get_global_config(self) -> Dict[str, Any]:
        """Parse global Claude Code configuration."""
        config_path = Path.home() / '.claude' / 'settings.json'
        config = {
            'exists': config_path.exists(),
            'hooks': [],
            'env_vars': [],
            'mcp_servers': [],
            'permissions': []
        }

        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    settings = json.load(f)

                if isinstance(settings, dict):
                    if 'hooks' in settings and isinstance(settings['hooks'], dict):
                        config['hooks'] = list(settings['hooks'].keys())
                    if 'env' in settings and isinstance(settings['env'], dict):
                        config['env_vars'] = list(settings['env'].keys())
                    if 'mcp_servers' in settings:
                        servers = settings['mcp_servers']
                        if isinstance(servers, dict):
                            config['mcp_servers'] = list(servers.keys())
                    if 'permissions' in settings:
                        perms = settings['permissions']
                        if isinstance(perms, dict):
                            config['permissions'] = list(perms.keys())
            except (json.JSONDecodeError, IOError):
                pass

        return config

    def check_project_static_config(self, project_path: str) -> Dict[str, bool]:
        """Check for static configuration files in project."""
        project_dir = Path(project_path)

        return {
            'has_claude_md': (project_dir / 'CLAUDE.md').exists(),
            'has_settings_json': (project_dir / '.claude' / 'settings.json').exists(),
            'has_rules': (project_dir / '.claude' / 'rules').exists(),
            'has_memory': (project_dir / 'memory').exists(),
            'has_sentinel_json': (project_dir / '.sentinel.json').exists(),
        }

    def scan_projects(self) -> List[Tuple[str, str]]:
        """Scan ~/.claude/projects for all projects with sessions.

        Returns: List of (project_hash, resolved_path) tuples
        """
        projects_dir = Path.home() / '.claude' / 'projects'
        if not projects_dir.exists():
            return []

        projects = []
        for project_hash_dir in projects_dir.iterdir():
            if not project_hash_dir.is_dir():
                continue

            project_hash = project_hash_dir.name

            # Check if directory has any .jsonl files
            if list(project_hash_dir.glob('**/*.jsonl')):
                resolved_path = self.resolve_project_path(project_hash)
                projects.append((project_hash, resolved_path))

        return sorted(projects)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze Claude Code session usage metrics'
    )
    parser.add_argument(
        '--project',
        type=str,
        help='Analyze single project (path or hash)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Analyze all projects with sessions'
    )
    parser.add_argument(
        '--global',
        action='store_true',
        dest='global_mode',
        help='Global mode (includes --all + global config)'
    )

    args = parser.parse_args()

    analyzer = SessionAnalyzer()

    # Determine mode
    if args.global_mode:
        args.all = True

    # Analyze projects
    project_results = {}

    if args.project:
        # Single project analysis
        project_path = args.project
        metrics, has_sessions = analyzer.analyze_project(project_path)

        if has_sessions:
            project_results[project_path] = {
                **metrics,
                'static_config': analyzer.check_project_static_config(project_path),
            }

    elif args.all or args.global_mode:
        # Multi-project analysis
        projects = analyzer.scan_projects()

        for project_hash, resolved_path in projects:
            project_home = Path.home() / '.claude' / 'projects' / project_hash
            metrics, has_sessions = analyzer.analyze_project(str(project_home))

            if has_sessions:
                project_results[resolved_path] = {
                    **metrics,
                    'static_config': analyzer.check_project_static_config(resolved_path),
                }

    # Build output
    output = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'period': {
            'mode': 'global' if args.global_mode else ('all' if args.all else 'single'),
            'projects_analyzed': len(project_results),
        },
        'global': analyzer.get_global_config() if args.global_mode else None,
        'projects': project_results,
    }

    # Aggregate statistics
    if project_results:
        aggregate_tools = defaultdict(int)
        aggregate_skills = defaultdict(int)
        aggregate_features = defaultdict(bool)

        for project_metrics in project_results.values():
            if 'tools' in project_metrics and 'by_name' in project_metrics['tools']:
                for tool_name, tool_data in project_metrics['tools']['by_name'].items():
                    aggregate_tools[tool_name] += tool_data['count']

            if 'skills_used' in project_metrics:
                for skill_name, count in project_metrics['skills_used'].items():
                    aggregate_skills[skill_name] += count

            if 'features_detected' in project_metrics:
                for feature, enabled in project_metrics['features_detected'].items():
                    if enabled:
                        aggregate_features[feature] = True

        # Build aggregated tools dict
        total_tools = sum(aggregate_tools.values())
        tools_by_name = {}
        for tool_name in sorted(aggregate_tools.keys(),
                               key=lambda x: aggregate_tools[x], reverse=True):
            count = aggregate_tools[tool_name]
            tools_by_name[tool_name] = {
                'count': count,
                'percentage': round(100 * count / total_tools, 1) if total_tools > 0 else 0
            }

        output['aggregated'] = {
            'tools': {
                'total': total_tools,
                'unique_tools': len(aggregate_tools),
                'by_name': tools_by_name
            },
            'skills_used': dict(aggregate_skills),
            'features_detected': {k: v for k, v in aggregate_features.items() if v},
        }

    # Output JSON
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
