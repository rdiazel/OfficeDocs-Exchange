---
title: "fill in article title..."
ms.author: ridia
author: rdiazel
manager:ercastro 
ms.audience: ITPro
ms.topic: article
ms.prod: exchange-server-it-pro
localization_priority: Normal
description: "fill in desc..."
---

# **Summary**
The purpose of this document is to help to providing a guide to start mitigating brute force password spray attacks when disabling legacy from the root in your company cannot be done, because this may affect some users or applications that work with legacy clients.

This granularity allows start applying changes to specific groups or users based on their attributes.


## **Part I. Query your users in Active Directory**

**Active Directory**

**The steps provided in this part are optional and were included to help identifying the users for which the policy will be applied**

The attribute we will use is the department name as it is one of the most common attributes used to tag users depending on their department and roles.

The following link shows all Active Directory user extended properties:

https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx

There are other ways to disable legacy authentication in Active Directory using GPOs if needed. For example, this one was applied to Win10 Computers disabling legacy authentication:
Blocking basic authentication at the OS level for Windows 10 computers by setting Allow basic authentication to disabled in the GPO Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service”.

In this part, we will query Active Directory users and Groups, to determine what attributes users have and which one we want to use to filter in Exchange Online service.

**Get a list of all your AD Groups**
-  In your AD server, open PowerShell as an Administrator. (right click, select Run as administrator)

```PowerShell
Get-ADGroup -filter * | select -Property name
```

- You can also export the outputs to a text file.

```PowerShell
Get-ADGroup -filter * | select -Property name | Out-File C:\Users\textfile.txt
```

**Get the members of a group**


Now that we have all our groups, we can query which users belong to those groups and create a list based on any of their attributes. I recommend using attribute as this value is unique for each user.

Get-ADGroupMember -Identity <groupname> | select -Property ObjectGuid

**Set or get attributes**.

- Now we want to find or set, one specific attribute that will be Synced with Exchange Online to filter users based on this attribute.

This will help us to disable legacy protocols for specific groups, and make sure that production will not be affected to the entire company.

**If your company have OUs and GPs applied to set this attribute, you may not need to do this, but you can query all the users to confirm that these attributes have been applied already or not. If there are no policies set for this, it may be a good time to set them**.

- These commands set the attribute “department” as “developer”, for users that belong to a group named “developer”, obtained in the previous steps.

```PowerShell
$variable1 = Get-ADGroupMember -Identity "<groupname>" | select -expandproperty "objectGUID"
Foreach ($user in $variable1) {set-ADUser -identity $user.ToString()  -Add @{department="<department_name>"}}
```

- Query your users to make sure attribute was applied or if they already have it.

```PowerShell
Get-ADUser -filter {(department -eq '<department_name>')} -Properties Department
```

- This command returns the ObjectGuid, name or all properties for all users based on the previous conditions, in case this is needed to create a list of these users

```PowerShell
Get-ADUser -filter {(department -eq '<department_name>')} -Properties department | select -Property objectguid
Get-ADUser -filter {(department -eq '<department_name>')} -Properties department | select -Property name
Get-ADUser -filter {(department -eq '<department_name>')} -Properties department | select -Property *
```

Once this is completed, and you have determined which groups you want to start disabling legacy for, we can continue with the next steps.

### Part II. Disabling legacy in EXO

**Before you continue, it is important to know that attributes for users that exist on-premises are Synced to Exchange Online, only when users have a valid Exchange License**.

If you need to check this, we can run different queries in Exchange Online using PowerShell.

If you want to apply a license to any given user or group, you can go to **https://portal.office.com > Billing > Subscriptions and select the license you want to enable for users**.

**Before continuing, please stop and read the document provided in the following link to understand how basic authentication works and get additional details**.

The following instructions are all based on Microsoft official documentation found on this link:

[disable-basic-authentication-in-exchange-online](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online)

I am including additional information and fully working commands to make this task easier to complete.

- Connecting to Exchange Online with PowerShell

```Powershell
#require all PowerShell scripts that you download from the internet are signed by a trusted publisher
Set-ExecutionPolicy RemoteSigned
#get credentials
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session -DisableNameChecking
#If you don't receive any errors, you connected successfully
```
Quick test is to run an Exchange Online cmdlet, for example, Get-Mailbox, and see the results. If no error is returned, you connected successfully.

**Let’s run some queries. We can determine if users have email client enabled by filtering by department**.

We can also see all their attributes that are Synced to Exchange Online.

- Get a full list of users with mailbox enabled:

```Powershell
Get-User -filter {(RecipientType -eq 'UserMailbox')}
```

- Get users with mail client enabled and from a specific department

```Powershell
Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<department_name')}
```

**(The attribute “department” was verified or set in Part I )**

**Create a policy to disable legacy authentication**

To determine what protocols or services needs to be disabled on the policy, please check the document provided with a list of legacy clients and protocols used:

[Authentication policy procedures in Exchange Online](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online?redirectSourcePath=%252fen-ie%252farticle%252fDisable-Basic-authentication-in-Exchange-Online-bba2059a-7242-41d0-bb3f-baaf7ec1abd7#authentication-policy-procedures-in-exchange-online)

- Create a policy to disable legacy

```PowerShell
New-AuthenticationPolicy -Name '<policy_name>'>
```

- To get policy configuration:

```PowerShell
Get-AuthenticationPolicy -Identity '<policy_name>'
```

- To modify the settings of the policy

For detailed syntax and parameters information, see New-AuthenticationPolicy cmdlets.

```PowerShell
Set-AuthenticationPolicy -Identity '<policy_name>'
```

Parameters:

```PowerShell
-AllowBasicAuthActiveSync: $false or $true
-AllowBasicAuthAutodiscover: $false or $true
-AllowBasicAuthImap: $false or $true
-AllowBasicAuthMapi: $false or $true
-AllowBasicAuthOfflineAddressBook: $false or $true
-AllowBasicAuthOutlookService: $false or $true
-AllowBasicAuthPop: $false or $true
-AllowBasicAuthPowershell: $false or $true
-AllowBasicAuthReportingWebServices: $false or $true
-AllowBasicAuthRest: $false or $true
-AllowBasicAuthRpc: $false or $true
-AllowBasicAuthSmtp: $false or $true
-AllowBasicAuthWebServices: $false or $true 
```



- Apply the policy to all users in the same department

```PowerShell
$variable1 = Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<departmentname>')}
$variable2 = $variable1.windowsemailaddress
$variable2 | foreach {Set-User -Identity $_ -AuthenticationPolicy "<policyname>"}
```

- You can query user’s attributes to make sure policy was applied.

```PowerShell
Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<departmentname>')} | select -Property *
```

The fundamental lesson I learned when working on this topic about the Filter parameter for on-premises Exchange Server: use the distinguished name (DN) of the object. Other unique values like Name, Alias, EmailAddress, etc. that should work don't.

So, run the command:

```PowerShell
Get-AuthenticationPolicy | Format-List Name,DistinguishedName
```PowerShell

And then use the DN value for the filter:

```PowerShell
Get-User -Filter {AuthenticationPolicy -eq '<DN of Disable Legacy auth policy>'}
```

This will complete the steps to disable Basic Authentication for one specific group of users.


- If you need to delete a policy

```PowerShell
remove-AuthenticationPolicy -Identity "<PolicyIdentity>”
```

- If you want to remove users for specific group from the policy:

```PowerShell
$variable1 = Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<departmentname>')}
$variable2 = $variable1.windowsemailaddress
$variable2 | foreach {Set-User -Identity $_ -AuthenticationPolicy "$null"}
```


#### **Testing your policy**

We recommend testing a policy before making changes in a production environment.

- The following steps will create a policy to disable ActiveSync, Pop, Imap, SMTP protocols and it will be applied to only one user of your choice to test.

```PowerShell
#require all PowerShell scripts that you download from the internet are signed by a trusted publisher
Set-ExecutionPolicy RemoteSigned
#get credentials to connect to EXO
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session -DisableNameChecking
#If you don't receive any errors, you connected successfully.
```

```PowerShell
#enable modern authentication
#Modern authentication is enabled by default. Please make sure modern authentication is enabled.
Get-OrganizationConfig | select -Property oaut2*
```

```PowerShell
# enable modern authentication
Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
```

```PowerShell
#disable modern authentication
Set-OrganizationConfig -OAuth2ClientProfileEnabled $false
```

[Enable or disable modern authentication in Exchange Online](https://support.office.com/article/58018196-f918-49cd-8238-56f57f38d662).

```PowerShell
#create the new policy, disabled legacy for POP,IMAP, SMTP and ActiveSync</span>
New-AuthenticationPolicy -Name ‘policyname’ -AllowBasicAuthActiveSync:$false  -AllowBasicAuthPop:$false -AllowBasicAuthSmtp:$false -AllowBasicAuthImap:$false
```

```PowerShell
#applying policy to user
$user= Get-User -ResultSize unlimited -Filter {(name -eq 'username')} | select -Property windowsemailaddress
Set-User -Identity $user.windowsemailaddress -AuthenticationPolicy 'policyname'
```

##### **Contact & Feedback**

If you have any question, concern or feedback, please send an email to ridia@microsoft.com or contact Azure Identity team.

References:

[disable basic authentication in exchange online](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online).
[remove-authenticationpolicy](https://docs.microsoft.com/en-us/powershell/module/exchange/organization/remove-authenticationpolicy?view=exchange-ps).
[set-authenticationpolicy](https://docs.microsoft.com/en-us/powershell/module/exchange/organization/set-authenticationpolicy?view=exchange-ps).
[Enable or disable modern authentication in Exchange Online](https://support.office.com/article/58018196-f918-49cd-8238-56f57f38d662).


