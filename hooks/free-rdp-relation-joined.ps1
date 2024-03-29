#
# Copyright 2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
$ErrorActionPreference = "Stop"

Import-Module JujuLogging


try {
    Import-Module JujuHooks
    Import-Module JujuUtils
    Import-Module FreeRdpHooks

    $rdpProxySubnet = Get-JujuCharmConfig -Scope "rdp-proxy-subnet"
    $ipAddress = Get-IPFromSubnet -Subnet "$rdpProxySubnet"
    if (! $ipAddress) {
        $ipAddress = Get-JujuUnitPrivateIP
    }
    $port = Get-JujuCharmConfig -Scope "http-port"
    $url = "http://{0}:{1}" -f @($ipAddress, $port)

    $settings = @{
        "enabled" = $true;
        "html5_proxy_base_url" = $url
    }

    $rids = Get-JujuRelationIds -Relation "free-rdp"
    foreach ($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings $settings
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
