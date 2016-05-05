$Group = Read-Host 'Specify Group';
[void][System.Reflection.Assembly]::LoadWithPartialName('System.DirectoryServices.AccountManagement');
([System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity([System.DirectoryServices.AccountManagement.ContextType]::Domain,$Group)).GetMembers(1);
