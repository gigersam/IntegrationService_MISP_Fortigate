# Integration Service for Fortigate-MISP
This repository contains a small hobby project designed to check IP addresses to determine if they are mentioned in any MISP event. If they are, they will be added to a group, which can then be blocked.

To clean up old IP address objects on the Fortigate, there is a housekeeping service. The housekeeping service will also update the MISP feeds via an API.

You can find more information in this post: [My Blog](https://samuelgiger.com/blog/post/FortigateMISPIntegrationIntegrationService).