#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034

#Generic plugin vars
plugin_name="Missing dependencies auto-installation"
plugin_description="A plugin to autoinstall missing dependencies on some Operating Systems"
plugin_author="v1s1t0r"

#Enabled 1 / Disabled 0 - Set this plugin as enabled - Default value 1
plugin_enabled=1

#Plugin requirements
#Set airgeddon versions to apply this plugin (leave blank to set no limits, minimum version recommended is 10.0 on which plugins feature was added)
plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""
#Set only one element in the array "*" to affect all distros, otherwise add them one by one with the name which airgeddon uses for that distro (examples "BlackArch", "Parrot")
plugin_distros_affected=("Kali" "Parrot")
