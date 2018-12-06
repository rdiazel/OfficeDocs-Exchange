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


PART I Query users and groups in Active Directory


This document provides steps to query your own environment and helps to determine which users belongs to which groups and what attributes they have.
The purpose of this guide is to help providing a guide to start mitigating brute force password spray attacks, when disabling legacy at all in your company can not be done, because this may affect some users or applications that works with legacy clients.
This granularity allows to start applying changes to specific groups or users based on their attributes.


The attribute to use, is one of your choice and this give you flexibility to complete this setup depending on your company requirements.
The following link shows all AD user extended properties: https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
 
There are other ways to disable legacy authentication in AD using GPOs if needed. For example, this one was applied to Win10 Computers disabling legacy authentication:
“Blocking basic authentication at the OS level for Windows 10 computers by setting Allow basic authenication to disabled in the GPO Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service.”

Active Directory

In this part, we will query AD users and Groups, to determine what attributes users have and which one we want to use to filter in Exchange Online service.

1.Get a list of all of your AD Groups.

               In your AD server, open powershell as an Administrator. (right click, select Run as administrator)

Get-ADGroup -filter * | select -Property name

               You can also export the outputs to a text file.

Get-ADGroup -filter * | select -Property name | Out-File C:\Users\username\ADgroup.txt

2.Get the members of a group.

Now that we have all our groups, we can query which users belongs to those groups and create a list based on any of their attributes. I recommend using ObjectGuid as this value is unique for each user.

Get-ADGroupMember -Identity <groupname> | select -Property objectguid

3.Set or get attributes.

Now we want to find or set, one specific attribute that will be Synced with Exchange Online to filter users based on this attribute.
This will help us to disable legacy protocols for specific groups, and make sure that production will not be affected to the entire company.

In these steps, I will set the attribute “department” as “developer”, for users that belong to a group named “developer” obtained in the previous steps.

*If your company have OUs and GPs applied to set this attribute, you may not need to do this, but you can query to make sure all users have these attributes applied already or not. If there are no policies set for this, it may be a good time to set it.
  

These commands set the attribute “department” = “developer”, for users that belong to a group named “developer” obtained in the previous steps.
 
$variable1 = Get-ADGroupMember -Identity "<groupname>" | select -expandproperty "objectGUID"
Foreach ($user in $variable1) {set-ADUser -identity $user.ToString()  -Add @{department="<department_name>"}}
 

Query your users to make sure attribute was applied or if they already have it.

Get-ADUser -filter {(department -eq '<department_name>')} -Properties Department

This command returns the ObjectGuid, name or all properties for all users based on the previous conditions in case this is needed to create a list of these users

Get-ADUser -filter {(department -eq '<department_name>')} -Properties department | select -Property objectguid
Get-ADUser -filter {(department -eq '<department_name>')} -Properties department | select -Property name
Get-ADUser -filter {(department -eq '<department_name>')} -Properties department | select -Property *

Once this is completed, and you have determined which groups you want to start disabling legacy for, we can continue with the next steps.
 

PART II Disabling legacy in EXO

Before you continue, it is important to know that attributes for users that exist on-prem are Synced to Exchange Online, only when users have a valid Exchange License.


If you need to check this, we can run different queries in EXO PowerShell. If you want to apply a license to any given user or group, you can go to portal.office.com>Billing>Subscriptions and select the license you want to enable for users.

**Before continuing, please stop and read the document provided in the following link to understand how basic authentication works and get additional details.


The following instructions are all based on Microsoft official documentation found on this link:
https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online


I am including additional information and full working commands to make this task easier to complete.

Connect to EXO

#require all PowerShell scripts that you download from the internet are signed by a trusted publisher

Set-ExecutionPolicy RemoteSigned 

#get credentials to connect to EXO

$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session -DisableNameChecking

#If you don't receive any errors, you connected successfully.

# quick test is to run an Exchange Online cmdlet, for example, Get-Mailbox, and see the results.

Let’s run some queries. We can determine if users have email client enabled and filter by department.

We can also see all their attributes that are Synced to EXO.


Get a full list of users with mailbox enabled:

Get-User -filter {(RecipientType -eq 'UserMailbox')}

Get users with mail client enabled and from a specific department

Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like 'departmentname')}

(The attribute “department” was verified or set in Part I )

2. Create a policy to disable legacy authentication.

To determine what needs to be disabled on that policy, please check the document provided: https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online

New-AuthenticationPolicy -Name "<policyname>"

To get policy configuration:

Get-AuthenticationPolicy -Identity "<policyname>"

To modify the settings of the policy

For detailed syntax and parameter information, see New-AuthenticationPolicy.

Set-AuthenticationPolicy -Identity <policyname>

Parameters:

   -AllowBasicAuthActiveSync:$false or $true

   -AllowBasicAuthAutodiscover:$false or $true

   -AllowBasicAuthImap:$false or $true

   -AllowBasicAuthMapi:$false or $true

   -AllowBasicAuthOfflineAddressBook:$false or $true

   -AllowBasicAuthOutlookService:$false or $true

   -AllowBasicAuthPop:$false or $true

   -AllowBasicAuthPowershell:$false or $true

   -AllowBasicAuthReportingWebServices:$false or $true

   -AllowBasicAuthRest:$false or $true

   -AllowBasicAuthRpc:$false or $true

   -AllowBasicAuthSmtp:$false or $true

   -AllowBasicAuthWebServices:$false or $true
 

Apply the policy to all users in the same department
 

$variable1 = Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<departmentname>')}

$variable2 = $variable1.windowsemailaddress

$variable2 | foreach {Set-User -Identity $_ -AuthenticationPolicy "<policyname>"}


You can query the users attributes to make sure policy was applied.

Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<departmentname>')} | select -Property *

Filtering by Authentication policy does not work*

This will complete the steps to disable Basic Authentication for one specific group of users.

If you need to delete a policy

remove-AuthenticationPolicy -Identity <PolicyIdentity>

If you want to remove users for specific group from the policy:
 

$variable1 = Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<departmentname>')}

$variable2 = $variable1.windowsemailaddress

$variable2 | foreach {Set-User -Identity $_ -AuthenticationPolicy "$null"}


Referrences:

https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online

https://docs.microsoft.com/en-us/powershell/module/exchange/organization/remove-authenticationpolicy?view=exchange-ps

https://blogs.technet.microsoft.com/exchange/2018/10/17/disabling-basic-authentication-in-exchange-online-public-preview-now-available/

https://docs.microsoft.com/en-us/powershell/module/exchange/organization/set-authenticationpolicy?view=exchange-ps

https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx

https://support.office.com/en-us/article/enable-or-disable-modern-authentication-in-exchange-online-58018196-f918-49cd-8238-56f57f38d662?ui=en-US&rs=en-US&ad=US

adgroupmember.png
