param(
    [string]$ApplicationInsightsApiKey = $Env:Deployment_Telemetry_Instrumentation_Key,
    [string]$Edition = $Env:SonarQubeEdition,
    [string]$Version = $Env:SonarQubeVersion
)

function TrackTimedEvent {
    param (
        [string]$InstrumentationKey,
        [string]$EventName,
        [scriptblock]$ScriptBlock,
        [Object[]]$ScriptBlockArguments
    )

    [System.Diagnostics.Stopwatch]$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ScriptBlockArguments
    $stopwatch.Stop()

    if ($InstrumentationKey) {
        $uniqueId = ''
        if ($Env:WEBSITE_INSTANCE_ID) {
            $uniqueId = $Env:WEBSITE_INSTANCE_ID.substring(5, 15)
        }

        $properties = @{
            "Location"        = $Env:REGION_NAME;
            "SKU"             = $Env:WEBSITE_SKU;
            "Processor Count" = $Env:NUMBER_OF_PROCESSORS;
            "Always On"       = $Env:WEBSITE_SCM_ALWAYS_ON_ENABLED;
            "UID"             = $uniqueId
        }

        $measurements = @{
            'duration (ms)' = $stopwatch.ElapsedMilliseconds
        }

        $body = ConvertTo-Json -Depth 5 -InputObject @{
            name = "Microsoft.ApplicationInsights.Dev.$InstrumentationKey.Event";
            time = [Datetime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            iKey = $InstrumentationKey;
            data = @{
                baseType = "EventData";
                baseData = @{
                    ver          = 2;
                    name         = $EventName;
                    properties   = $properties;
                    measurements = $measurements;
                }
            };
        }

        Invoke-RestMethod -Method POST -Uri "https://dc.services.visualstudio.com/v2/track" -ContentType "application/json" -Body $body | Out-Null
    }
}

TrackTimedEvent -InstrumentationKey $ApplicationInsightsApiKey -EventName 'Download And Extract Binaries' -ScriptBlock {
    Write-Output 'Copy wwwroot folder'
    xcopy wwwroot ..\wwwroot /YI

    Write-Output 'Setting Security to TLS 1.2'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Output 'Prevent the progress meter from trying to access the console'
    $global:progressPreference = 'SilentlyContinue'
    
    if (!$Version -or ($Version -ieq 'Latest')) {
        # binaries.sonarsource.com moved to S3 and is not easily searchable anymore. Getting the latest version from GitHub releases.
        $releasesFromApi = (Invoke-WebRequest -Uri 'https://api.github.com/repos/SonarSource/sonarqube/releases' -UseBasicParsing).Content
        $releasesPS = $releasesFromApi | ConvertFrom-Json
        $Version = $releasesPS.Name | Sort-Object -Descending | Select-Object -First 1
        Write-Output "Found the latest release to be $Version"
    }

    if (!$Edition) {
        $Edition = 'Community'
    }

    $downloadFolder = 'Distribution/sonarqube' # Community Edition
    $fileNamePrefix = 'sonarqube' # Community Edition
    switch ($Edition) {
        'Developer' { 
            $downloadFolder = 'CommercialDistribution/sonarqube-developer'
            $fileNamePrefix = 'sonarqube-developer'
        }
        'Enterprise' { 
            $downloadFolder = 'CommercialDistribution/sonarqube-enterprise'
            $fileNamePrefix = 'sonarqube-enterprise'
        }
        'Data Center' { 
            $downloadFolder = 'CommercialDistribution/sonarqube-datacenter'
            $fileNamePrefix = 'sonarqube-datacenter'
        }
    }

    $base_fileName = "$fileNamePrefix-$Version"
    $fileName = "$base_fileName.zip"
    $downloadUri = "https://binaries.sonarsource.com/$downloadFolder/$fileName"

    if (!$downloadUri -or !$fileName) {
        throw 'Could not get download uri or filename.'
    }

    Write-Output "Downloading '$downloadUri'"
    $outputFile = "..\wwwroot\$fileName"
    Invoke-WebRequest -Uri $downloadUri -OutFile $outputFile -UseBasicParsing
    Write-Output 'Done downloading file'

    TrackTimedEvent -InstrumentationKey $ApplicationInsightsApiKey -EventName 'Extract Binaries' -ScriptBlockArguments $outputFile -ScriptBlock {
        param([string]$outputFile)
        Write-Output 'Extracting zip'
        Expand-Archive -Path $outputFile -DestinationPath '..\wwwroot' -Force
        Write-Output 'Extraction complete'
    }

    $sonarqube_outputPath = "..\wwwroot\$base_fileName"
    TrackTimedEvent -InstrumentationKey $ApplicationInsightsApiKey -EventName 'Download Additional SonarQube Plugins' -ScriptBlockArguments $sonarqube_outputPath -ScriptBlock {
        param([string]$sonarqube_outputPath)
        function Get-SonarQubeAdditionalFile {
            [CmdletBinding()]
            param (
                [Parameter()][String]$downloadUri,
                [Parameter()][String]$outputPath
            )
            $plugin_filename = ([uri]$downloadUri).Segments[-1]
            Write-Output "Downloading: '$downloadUri'"
            $outputFullPath = $outputPath + $plugin_filename
            Invoke-WebRequest -Uri $downloadUri -OutFile $outputFullPath -UseBasicParsing
            Write-Output 'Done downloading file'
        }
    
        # Just add SonarQube Plugins URL on that Array
        $sonar_plugins_url = @(
            "https://github.com/QualInsight/qualinsight-plugins-sonarqube-smell/releases/download/qualinsight-plugins-sonarqube-smell-4.0.0/qualinsight-sonarqube-smell-plugin-4.0.0.jar",
            "https://github.com/sbaudoin/sonar-ansible/releases/download/v2.5.1/sonar-ansible-extras-plugin-2.5.1.jar",
            "https://github.com/sbaudoin/sonar-ansible/releases/download/v2.5.1/sonar-ansible-plugin-2.5.1.jar",
            "https://github.com/hkamel/sonar-auth-aad/releases/download/1.2.0/sonar-auth-aad-plugin-1.2.0.jar",
            "https://github.com/galexandre/sonar-cobertura/releases/download/2.0/sonar-cobertura-plugin-2.0.jar",
            "https://github.com/dependency-check/dependency-check-sonar-plugin/releases/download/3.0.1/sonar-dependency-check-plugin-3.0.1.jar",
            "https://github.com/cnescatlab/sonar-hadolint-plugin/releases/download/1.1.0/sonar-hadolint-plugin-1.1.0.jar",
            "https://s01.oss.sonatype.org/content/repositories/releases/com/sonar-scala/sonar-scala_2.13/8.9.0/sonar-scala_2.13-8.9.0-assembly.jar",
            "https://github.com/sbaudoin/sonar-shellcheck/releases/download/v2.5.0/sonar-shellcheck-plugin-2.5.0.jar",
            "https://github.com/kwoding/sonar-webdriver-plugin/releases/download/sonar-webdriver-plugin-1.0.10/sonar-webdriver-plugin-1.0.10.jar",
            "https://github.com/sbaudoin/sonar-yaml/releases/download/v1.7.0/sonar-yaml-plugin-1.7.0.jar",
            "https://github.com/mc1arke/sonarqube-community-branch-plugin/releases/download/1.10.0/sonarqube-community-branch-plugin-1.10.0.jar"
        )

        $outputPath = "$sonarqube_outputPath\extensions\plugins\"
        foreach ($plugin_url in $sonar_plugins_url) {
            Get-SonarQubeAdditionalFile -downloadUri $plugin_url -outputPath $outputPath
        }

        Write-Output 'Delete sonar-scala-plugin-*.jar to avoid conflict with sonar-scala_2.13-8.9.0-assembly community version.'
        $outputPath = "$sonarqube_outputPath\lib\extensions\"
        $sonar_scala_files = Get-ChildItem "$outputPath*" -Filter 'sonar-scala-plugin-*.jar'
        Write-Output "Deleting SonarQube sonar-scala-plugin-*.jar: $sonar_scala_files"
        $sonar_scala_files | Remove-Item

        Write-Output 'Clean up original SonarQube JDBC mssql driver folder.'
        $outputPath = "$sonarqube_outputPath\lib\jdbc\mssql\"
        $jdbc_driver_files = Get-ChildItem "$outputPath*" -Filter '*.jar'
        Write-Output "Deleting SonarQube JDBC mssql driver folder: $jdbc_driver_files"
        $jdbc_driver_files | Remove-Item

        Write-Output 'Download the new JDBC Driver 10.2.0.jre11'
        $jdbc_driver_url = "https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/10.2.0.jre11/mssql-jdbc-10.2.0.jre11.jar"
        Get-SonarQubeAdditionalFile -downloadUri $jdbc_driver_url -outputPath $outputPath
    }
}