---
title: "Disable legacy authentication in Exchange Online"
ms.author: ridia
author: rdiazel
manager:ercastro 
ms.audience: ITPro
ms.topic: article
ms.prod: exchange-server-it-pro
localization_priority: Normal
description: "Use this guide to start mitigating brute force password spray attacks when you cannot disable legacy from the root in your company."

---

# Disable legacy authentication in Exchange Online

When you cannot disable legacy from the root in your company because it may affect users or applications that work with legacy clients, use this guide to start mitigating brute force password spray attacks. This granularity allows you to start applying changes to specific groups or users based on their attributes.

## Step 1: Query your users in Active Directory

> [!Note]
> The instructions provided in this step are optional and are included to help you identify the users for which the policy will be applied.

The attribute we will use is the department name, as it is one of the most common attributes used to tag users depending on their department and roles.

To see all Active Directory user extended properties, go to [Active Directory: Get-ADUser Default and Extended Properties](https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx). 

There are other ways to disable legacy authentication in Active Directory using GPOs, if needed. For example, this one was applied to Windows 10 computers disabling legacy authentication:

```
"Blocking basic authentication at the OS level for Windows 10 computers by setting Allow basic authentication to disabled in the GPO Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service”.
```
Here we will query Active Directory users and groups to determine which attributes users have and which ones we want to use to filter in the Exchange Online service.

### Get a list of all your AD Groups

-  In your AD server, open PowerShell as an Administrator (right-click and select **Run as administrator**).

    ```PowerShell
    Get-ADGroup -filter * | select -Property name
    ```

- You can also export the outputs to a text file.

    ```PowerShell
    Get-ADGroup -filter * | select -Property name | Out-File C:\Users\textfile.txt
    ```

### Get the members of a group

Now that we have all our groups, we can query which users belong to those groups and create a list based on any of their attributes. We recommend using the attribute `ObjectGuid`, as this value is unique for each user.

```PowerShell
Get-ADGroupMember -Identity <groupname> | select -Property ObjectGuid
```

### Set or get attributes

Now we want to find or set one specific attribute that will be synced with Exchange Online to filter users based on this attribute. This will help us disable legacy protocols for specific groups and ensure that production will not affect the entire company.

> [!Note]
> If your company has OUs and GPs applied to set this attribute, you may not need to do this, but you can query all the users to confirm whether these attributes have been applied already. If there are no policies set for this, it may be a good time to set them.

- These commands set the attribute “department” as “developer”, for users that belong to a group named “developer”, obtained in the previous steps.

    ```PowerShell
    $variable1 = Get-ADGroupMember -Identity "<groupname>" | select -expandproperty "objectGUID"
    Foreach ($user in $variable1) {set-ADUser -identity $user.ToString()  -Add @{department="<department_name>"}}
    ```

- Query your users to make sure the attribute was applied or determine whether they already have it.

    ```PowerShell
    Get-ADUser -filter {(department -eq '<department_name>')} -Properties Department
    ```

- This command returns the ObjectGuid, name, or all properties for all users based on the previous conditions, in case this is needed to create a list of these users.

    ```PowerShell
    Get-ADUser -filter {(department -eq '<department_name>')} -Properties department | select -Property objectguid
    Get-ADUser -filter {(department -eq '<department_name>')} -Properties department | select -Property name
    Get-ADUser -filter {(department -eq '<department_name>')} -Properties department | select -Property *
    ```

When this is completed and you have determined which groups you want to start disabling legacy for, you can continue with the next step.

## Step 2: Disable legacy in Exchange Online

Before you continue, it is important to know that attributes for users that exist on premises are synced to Exchange Online only when users have a valid Exchange license. If you need to check this, you can run queries in Exchange Online using PowerShell.

To apply a license to any given user or group, go to **https://portal.office.com > Billing > Subscriptions** and select the license you want to enable for users.

> [!Important]
> Before continuing, please stop and read the document provided in the following link to understand how basic authentication works and get additional details.

The following instructions are all based on Microsoft official documentation found in [Disable Basic authentication in Exchange Online](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online).

Additional information and fully working commands are included here to make this task easier to complete.

- Connecting to Exchange Online with PowerShell

    ```Powershell
    #require all PowerShell scripts that you download from the internet are signed by a trusted publisher
    Set-ExecutionPolicy RemoteSigned
    #get credentials
    $UserCredential = Get-Credential
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -        Credential $UserCredential -Authentication Basic -AllowRedirection
    Import-PSSession $Session -DisableNameChecking
    #If you don't receive any errors, you connected successfully
    ```
To quickly test, run an Exchange Online cmdlet, such Get-Mailbox, and see the results. If no error is returned, you connected successfully.

**Let’s run some queries to determine whether users have email clients enabled by filtering by department.**

We can also see all their attributes that are synced to Exchange Online.

- Get a full list of users with mailbox enabled.

    ```Powershell
    Get-User -filter {(RecipientType -eq 'UserMailbox')}
    ```

- Get users with mail client enabled and from a specific department.

    ```Powershell
    Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<department_name')}
    ```

    > [!Note]
    > The attribute “department” was verified or set in Step 1.**

### Create a policy to disable legacy authentication

To determine what protocols or services needs to be disabled on the policy, check the document provided with a list of legacy clients and protocols used by reviewing [Authentication policy procedures in Exchange Online](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online#authentication-policy-procedures-in-exchange-online)

- Create a policy to disable legacy.

    ```PowerShell
    New-AuthenticationPolicy -Name '<policy_name>'>
    ```

- Get policy configuration.

    ```PowerShell
    Get-AuthenticationPolicy -Identity '<policy_name>'
    ```

- Modify the settings of the policy. For detailed syntax and parameters information, see New-AuthenticationPolicy cmdlets.

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

- Apply the policy to all users in the same department.

    ```PowerShell
    $variable1 = Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<departmentname>')}
    $variable2 = $variable1.windowsemailaddress
    $variable2 | foreach {Set-User -Identity $_ -AuthenticationPolicy "<policyname>"}
    ```

- Query users' attributes to make sure the policy was applied.

    ```PowerShell
    Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<departmentname>')} | select -Property *
    ```
> [!Important] When using the Filter parameter for on-premises Exchange Server, use the distinguished name (DN) of the object. Other unique values, such as Name, Alias, EmailAddress, etc., don't work.

Run the command.

```PowerShell
Get-AuthenticationPolicy | Format-List Name,DistinguishedName
```
And then use the DN value for the filter.

```PowerShell
Get-User -Filter {AuthenticationPolicy -eq '<DN of Disable Legacy auth policy>'}
```

This will complete the steps to disable Basic Authentication for one specific group of users.

- If you need to delete a policy, run the following.

    ```PowerShell
    remove-AuthenticationPolicy -Identity "<PolicyIdentity>”
    ```

- If you want to remove users for specific group from the policy, run the following.

    ```PowerShell
    $variable1 = Get-User -Filter {(RecipientType -eq 'UserMailbox') -and (Department -like '<departmentname>')}
    $variable2 = $variable1.windowsemailaddress
    $variable2 | foreach {Set-User -Identity $_ -AuthenticationPolicy "$null"}
    ```

### Test your policy

We recommend testing a policy before making changes in a production environment.

The following steps will create a policy to disable ActiveSync, Pop, Imap, and SMTP protocols, and it will be applied to only one user of your choice to test.

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

## Contact and feedback

If you have any questions, concerns, or feedback, please send an email to ridia@microsoft.com or contact the Azure Identity team.

References:

[Disable Basic authentication in Exchange Online](https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online)
[Remove-AuthenticationPolicy](https://docs.microsoft.com/en-us/powershell/module/exchange/organization/remove-authenticationpolicy?view=exchange-ps)
[Set-AuthenticationPolicy](https://docs.microsoft.com/en-us/powershell/module/exchange/organization/set-authenticationpolicy?view=exchange-ps)
[Enable or disable modern authentication in Exchange Online](https://support.office.com/article/58018196-f918-49cd-8238-56f57f38d662)


