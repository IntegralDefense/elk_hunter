![elkhunter logo](/images/elkhunter_logo.png)

# ELK Hunter

![elkhunter ecosystem fit](/images/elkhunter_ecosystem.png)
## Features:
- daemon mode for continuous automated hunting/searching
- full coverage mode so you never miss data to search across
- lucene syntax support
- additional custom search parameters for those items elasticsearch doesn't support ootb
- integration with ACE to manage and correlate alerts produced by your searches/hunts

## Why?
When creating searches/hunts on items you want to be made aware of within your logs from a security perspective, manageability and coverage over time are important. We couldn't find anything that exists that provides this functionality.

## Use Case Example
Let's say you are reading security related information like this https://twitter.com/jackcr/status/907573104960045056?refsrc=email&s=11.
You decide to see how often "://" and Start-Process in a PS command exist in your environment. In kibana you search for:

    command_line:*Start\-Process* AND command_line:*\:\/\/*

Maybe you find some interesting application, but it turns out to be legitimate within your environment (or you find evil and respond). So, now you know it is legitimate and never want to have those results. Now your search is:

    command_line:*Start\-Process* AND command_line:*\:\/\/* AND
    -command_line:*\\stupid_internal_app.ps1*

Sweet, but now, you want to know whenever that search yields results right? That is what ELK Hunter is for.

## Setup & Run
1. clone the elk_hunter git repository (assume /opt/elk_hunter)
2. within etc, edit or create an ini file from the sample templates, specifically make sure your [elk] section has a uri item
3. symlink elk_hunter.ini to your ini file (elk_hunter uses elk_hunter.ini as the default configuration file)
4. create a rule & ini file - see "test_rules" directory for some examples
5. test your rules:

       python3 ./bin/elk_hunter.py -b /opt/elk_hunter -c etc/elk_hunter.ini -r test_rules cmd_ps1_url

6. once you have a good rule, run the daemon (and assuming you have ACE configured, have a nice alert in ACE whenever a search matches)

       python3 ./bin/elk_hunter.py -d --background -r production_rules -r more_rules

## Custom Options
The search ini samples include descriptions of the configurable parameters for full coverage, how often to run the search, result size limits, observable mappings for ACE correlation, etc.
Additionally, we have added some custom capability to extend the lucene search syntax.

- **--index:**
  - required field
  - specify the index within elasticsearch to run your search across
  - this is the same index you would pass to the curl command before the /\_search portion of the url GET /winlogs/\_search
  - **example**

        --index:winlogs

- **--search:**
  - required field
  - the lucene search to run (exact format that kibana discover search accepts)
  - comment your search with lines starting with "#"

        --search:path:*scvhost.exe*

- **--fields:**
  - optional field
  - **parameters**
    1. comma separated list of field names to output (this basically just adds the "\_sources" json to the search)
  - **example**

        --fields:command_line,username,hostname

- **--field-rename:**
  - optional field
  - **parameters**
  1. string with two field names separated by comma. the first item is the current field name, the second item is the name to change it to
  - **example**

        --field-rename:hostname,computer_name

- **--field-split:**
  - optional field
  - sometimes you want to create a new field from an existing field within a structure field, maybe for pulling out specific observables to pass to ACE
  - **parameters**
    1. new field name (the key within the resulting json document to create)
    2. field to run the split on
    3. the array item (base 0) of the split action for the given delimiter on the second parameter (field to run the split on)
    4. the delimiter specified with the \_\_delim: tag (think of this as being the param to a typical string.split() that yeilds an array, thus specify which array item you want to use to create the new field
  - **example** - if username='CORPDOMAIN\USERID', the following will create a field named 'userid' = 'USERID'
        --field-split:userid,username,1,__delim:'\'

- **--add-field:**
  - optional field
  - There are instances where you would like to add data elements based on existing fields to the output of the elasticsearch json results, but as far as I can tell that isn't possible with lucene, so we've added a --add-field parameter allowed in the search file.
  - **parameters**
    1. new field name (the key within the resulting json document to create)
    2. from field name (the field name that you want to extract data from to create the new field content)
    3. regex (regex for matching the content that should be put into the new field name contents)
  - **example** - this will add "bat_file" and "exe_file" field output to each result

        --index:your_index_name_for_your_data_in_elasticsearch
        --search:command_line:*\bat\"*\.exe\"*
        --add-field:bat_file,command_line,\"[^\"]+\.bat\"
        --add-field:exe_file,command_line,\"[^\"]+\.exe\"

- **--join-fields**
  - optional field
  - concatenate two fields into a new field
  - **parameters**
    1. new field name to create
    2. field names to join/concat separated by ","
    3. \_\_delim: character or string delimiter
  - **example** - this will create a new field named domain  = hostname\username

        --join-fields:domain,hostname,username,__delim:'\'

- **--filter-script:**
  - optional field
  - sometimes you just need to regex to find certain things within your data or write a small script. this custom parameter allows you to add a script to your query filter
  - **parameters**
    1. your script -> same as the value of the script  tag within a filter for dsl
  - **example** - maybe you want to find command line values that have more than 100 of the following characters in a row added to your lucene search:

        --filter-script:/[0-9a-zA-Z+\/=]{100,}/.matcher(doc['command_line'].value).find()

- **|pipe-field-output**
  - optional field
  - sometimes you need to join or search for items from one search to another search (across indexes or within). the direction I've seen from elastic is to format your data the way you need and/or use aggregates. from my testing & experience this was too much of a limitation, thus the implementation of this feature which pipes output from one search into the  search of the next search. there are a few requirements when using this feature.
  - limitations: the subsearch limitation of 10000 results (elasticsearch limitation)
  - all but the last search in a sequence of searches is required to have the **--fields** command in the search so that the next search is appended to with the results of the fields from the first search, which only supports one field.
  - **example** - say you have a system that when an autoruns key is created. and, say you want to get the metadata of the process that matched that autoruns creation. you would need to search for the autoruns changes and then search for the processes that matched. this searches for those autoruns created and pipes the process_guid to the next search.

        --index:*:carbonblack
        --search:watchlist_name:autoruns
        --fields:process_guid

        |pipe-field-output

        --index:*:carbonblack
        --search: ( *\.ps1* OR *\.bat* OR *java\.exe* OR etc...) AND
                -path:*youdaodictinstaller\.exe*

 - **example2** - maybe you want to hunt on just domain controller activity, but you don't want to keep a list up-to-date of domain controllers (maybe because they change too often, or maybe because you are lazy). you have access to a log source that identifies domain controllers and would like to use that to filter down your hunt. say you want to hunt on cmd.exe executing .bat files. this requires searching across two different indexes and joining on 2 different field names (because none of your log sources actually use the same field name for their content). this example uses a datasource that identifies domain controllers as well as antivirus alert data (just as an example)

        --index:*:carbonblack
        --search:host_type:domain_controller
        --fields:hostname --field-rename:hostname,computer_name

        |pipe-field-output

        --index:*antivirus_logs
        --search:action:allowed AND -RuleName:some_dumb_av_rule

