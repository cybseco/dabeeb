	
function Get-Banner{
 echo "
 
      **     **       *******   ******** ********     **     **                            
    ****   /**      /**////** /**///// /**/////     ****   /**                            
   **//**  /**      /**   /** /**      /**         **//**  /**                            
  **  //** /**      /*******  /******* /*******   **  //** /**                            
 **********/**      /**///**  /**////  /**////   **********/**                            
/**//////**/**      /**  //** /**      /**      /**//////**/**                            
/**     /**/********/**   //**/********/**      /**     /**/**                            
//      // //////// //     // //////// //       //      // //                             
                                                                                          
                                                                                          
                                                                                          
                                                                                          
                                                                                          
                                                                                          
                                                                                          
                                                                                          
                    ******** ********   ******  **     ** *******   ** ********** **    **
                   **////// /**/////   **////**/**    /**/**////** /**/////**/// //**  ** 
                  /**       /**       **    // /**    /**/**   /** /**    /**     //****  
                  /*********/******* /**       /**    /**/*******  /**    /**      //**   
                  ////////**/**////  /**       /**    /**/**///**  /**    /**       /**   
                         /**/**      //**    **/**    /**/**  //** /**    /**       /**   
                   ******** /******** //****** //******* /**   //**/**    /**       /**   
                  ////////  ////////   //////   ///////  //     // //     //        //    

"

}



function Get-SecSum{
    param (
        $strt,
        $nd
    )
    $filters = @{LogName = "Security"}
    if ($strt -ne $null) {
        $filters.StartTime = $strt
    }

    if ($nd -ne $null) {
        $filters.EndTime = $nd
    }
    Get-Banner
    Get-WinEvent -FilterHashtable $filters `
     | Group-Object -property ID `
     | Sort-Object -Property Count `
     | Format-Table -Property Count,Name
}

<#
	Using ID=1,
	
	Get-Sysmon-PS = Get Security Sysmon Process Create and print output in the form:
	
	TimeCreated: xxxxx
	PID : xxxxx
	Parent PID: xxxxx
	Command Line: xxxxx
	User: xxxxx
	Parent IMG: xxxxx
	
	 
#>

function Get-Sysmon-PS{
    param (
        $strt,
        $nd
    )
    $filters = @{LogName = "Microsoft-Windows-Sysmon/Operational";data=1}
    
    if ($strt -ne $null) {
        $filters.StartTime = $strt
    }

    if ($nd -ne $null) {
        $filters.EndTime = $nd
    }
    Get-Banner
    Get-WinEvent -FilterHashtable $filters `
	| Format-List `
	 TimeCreated `
	  @{Label = "PID"; Expression = {$_.properties[3].value}}, `
	   @{Label = "Parent PID"; Expression = {$_.properties[19].value}}, `
	    @{Label = "Command Line"; Expression = {$_.properties[10].value}}, `
	     @{Label = "User"; Expression = {$_.properties[12].value}}, `
	      @{Label = "Parent IMG"; Expression = {$_.properties[20].value}}

}

<#
	Using ID=3,
	
	Get-Sysmon-NC = Get Security Sysmon Process Create and print output in the form:
	TimeCreated: xxxxx
	IMG: xxxxx
	SRC IP: xxxxx
	SRC Port: xxxxx
	DST IP: xxxxx
	DST Port: xxxxx
	
#>

function Get-Sysmon-NC{
    param (
        $strt,
        $nd
    )
    $filters = @{LogName = "Microsoft-Windows-Sysmon/Operational";data=3}
    
    if ($strt -ne $null) {
        $filters.StartTime = $strt
    }

    if ($nd -ne $null) {
        $filters.EndTime = $nd
    }
    Get-Banner
    Get-WinEvent -FilterHashtable $filters `
	| Format-List `
	 TimeCreated `
	  @{Label = "IMG"; Expression = {$_.properties[4].value}}, `
	   @{Label = "SRC IP"; Expression = {$_.properties[9].value}}, `
	    @{Label = "SRC Port"; Expression = {$_.properties[11].value}}, `
	     @{Label = "DST IP"; Expression = {$_.properties[14].value}},  `
	      @{Label = "DST Port"; Expression = {$_.properties[16].value}}
}


function Get-Powershell {
 param (
  $strt,
  $nd
 )
 
 $fltrs = @{logname="microsoft-windows-powershell/operatinoal";ID=4103}
 if ($strt -ne $null) {
    $fltrs.StartTime = $strt
    }

    if ($nd -ne $null) {
        $fltrs.EndTime = $nd
    }
 Get-Banner
 Get-WinEvent -FilterHashtable $fltrs `
  | Format-List *
 

}

