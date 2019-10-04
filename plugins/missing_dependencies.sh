#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034

plugin_name="Missing dependencies auto-installation"
plugin_description="A plugin to autoinstall missing dependencies on some Operating Systems"
plugin_author="v1s1t0r"

plugin_enabled=1

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("Kali" "Parrot")

#TODO function hooking and plugin development
