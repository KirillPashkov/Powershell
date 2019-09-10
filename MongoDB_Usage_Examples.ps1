# We assume that the driver is installed via the MSI.

[string] $mongoDriverPath;
# Check to see if we are running the 64 bit version of Powershell. 
# See http://stackoverflow.com/questions/2897569/visual-studio-deployment-project-error-when-writing-to-registry
if ([intptr]::size -eq 8) {
    $mongoDriverPath = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.5\AssemblyFoldersEx\MongoDB CSharpDriver 1.0").'(default)';
}
else {
    $mongoDriverPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.5\AssemblyFoldersEx\MongoDB CSharpDriver 1.0").'(default)';
}
Add-Type -Path "$($mongoDriverPath)\MongoDB.Bson.dll";

[MongoDB.Bson.BsonDocument] $doc = @{
    "_id"= [MongoDB.Bson.ObjectId]::GenerateNewId();
    "FirstName"= "Justin";
    "LastName"= "Dearing";
    "PhoneNumbers"= [MongoDB.Bson.BsonDocument] @{
        'Home'= '718-555-1212';
        'Mobile'= '646-555-1212';
    };
};

Add-Type -Path "$($mongoDriverPath)\MongoDB.Driver.dll";

$db = [MongoDB.Driver.MongoDatabase]::Create('mongodb://localhost/powershell');
$collection = $db['example1'];
Write-Host "Insert";
$collection.Insert($doc);
$collection.FindOneById($doc['_id']);

$updates = @{'email'= 'justin@mongodb.org'};
$query = @{"_id"= $doc['_id']}

Write-Host "Update";
$collection.Update([MongoDB.Driver.QueryDocument]$query, [MongoDb.Driver.UpdateDocument]$updates);
$collection.FindOneById($doc['_id']);

Write-Host "Delete";
$collection.Remove([MongoDB.Driver.QueryDocument]$query);
$collection.FindOneById($doc['_id']);
