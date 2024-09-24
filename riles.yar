rule ExampleRule
   {
       strings:
           $suspicious_string = "malware"
       condition:
           $suspicious_string
   }