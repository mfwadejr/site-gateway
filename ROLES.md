# Roles

Site Gateway has three roles: **Administrator**, **Standard User**, and **Viewer**. A role controls two independent things: whether an account can open **Administration** at all, and whether it can change routing/access configuration versus only view it.

Everyone who is signed in — any role — can view the Dashboard, Hosted Sites, Proxy Hosts, Redirect Hosts, Streaming Hosts, Access Lists, Certificates, Performance, and Logs. My Account (profile, password, two-factor authentication) is available to every role and only ever affects your own account.

## Access matrix

| Area / action | Administrator | Standard User | Viewer |
|---|---|---|---|
| View Dashboard, Certificates, Performance, Logs | Yes | Yes | Yes |
| Create / edit / delete / enable-disable Hosted Sites, Proxy Hosts, Redirect Hosts, Streaming Hosts | Yes | Yes | No |
| Set custom icon on the above four kinds, plus Access Lists | Yes | Yes | No |
| Create / edit / delete Access Lists, including network rules and login credentials | Yes | Yes | No |
| Assign a Group to an Access List | Yes | No | No |
| View Groups list and membership | Yes | Yes (read-only) | Yes (read-only) |
| Create / edit / delete a Group | Yes | No | No |
| Open Administration (System, Users, Groups, Backups, API Access, Logs & Retention, Danger Zone) | Yes | No — not visible | No — not visible |
| Create / edit / delete / archive Users, reset a user's password | Yes | No | No |
| Run a certificate/domain check, resync gateway configuration after drift | Yes | No | No |
| Set icons on Users or API Tokens | Yes | No | No |
| My Account: change own password, manage own two-factor authentication | Yes | Yes | Yes |

## Notes

- For Standard and Viewer, Administration isn't merely read-only — it is entirely invisible, the same as every other Administrator-only row above.
- Icon assignment on Hosted Sites, Proxy Hosts, Redirect Hosts, Streaming Hosts, and Access Lists is **not** gated by role at the route level — Standard already has it, matching its general write access to those five kinds. Only Users and API Tokens fall through to administrator-only, because those two kinds sit outside the general operational-route pattern, not because of a specific icon rule.
- Site Gateway always keeps at least one active Administrator; an action that would leave zero is refused.
- An administrator cannot disable, archive, delete, or change the role of their own account — another administrator has to do that.

This table is the source of truth for the in-app "Users & Groups" documentation article and should be kept in sync with it.
