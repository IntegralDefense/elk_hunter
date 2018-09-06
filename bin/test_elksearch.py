import unittest
from elk_hunter import ELKSearch

class TestElkHunter(unittest.TestCase):
    #define searches with custom params to use for testing so elasticsearch datasets are not required for testing code
    #I assume that if the search syntax matches what needs to be sent to the execute command everything is in working order
    #test search parsing & --fields command
    index1 = "--index:*:test"
    fields1 = " --fields:process_guid,hostname,command_line"
    search1 = " --search: hostname:test AND path:*\\temp\\* AND -username:tester"
    fieldrename1 = " --field-rename:hostname,computer_name"
    addfield1 = " --add-field:bat_file,command_line,\"[^\"]+\.bat\""
    addfield2 = " --add-field:exe_file,command_line,\"[^\"]+\.exe\""
    fieldsplit1 = " --field-split:userid,username,1,__delim:'\\''"
    fieldsplit2 = " --field-split:domain,email_address,1,__delim:'@'"
    joinfield1 = " --join-fields:account,domain,username,__delim:'\\'"
    joinfield2 = " --join-fields:location,hostname,path,__delim:'@'"
    filterscript1 = " --filter-script:/[0-9a-zA-Z+\/=]{100,}/.matcher(doc['command_line'].value).find()"
    pipesearch1 = " |pipe-search-output"
    
    
    def getSearchObject(self):
        search_object = ELKSearch("test_rules", "test_search_fields")
        self.assertIsNotNone(search_object)
        return search_object

    def test_getSearchFileItem(self):
        search = self.index1 + self.search1 + self.fields1 + self.fieldrename1
        search_object = self.getSearchObject()

        #test parsing of --index: custom parameter
        index = search_object.getSearchFileItem(search,'--index:')
        self.assertEqual(index,'*:test')

        #test parsing of the --search: custom parameter
        search_text = search_object.getSearchFileItem(search,'--search:')
        self.assertEqual(search_text,'hostname:test AND path:*\\temp\\* AND -username:tester')
        
        #test parsing of the --fields: custom parameter
        fields = search_object.getSearchFileItem(search,'--fields:')
        self.assertEqual(fields,'process_guid,hostname,command_line')

        #test parsing of the --field-rename: custom parameter
        rename = search_object.getSearchFileItem(search,'--field-rename:')
        self.assertEqual(rename,'hostname,computer_name')

    def test_getSearchAddedFields(self):
        search = self.index1 + self.search1 + self.addfield1
        search_object = self.getSearchObject()
        added_fields = search_object.getSearchAddedFields(search)
        correct_fields = [{ 'from_field_name':'command_line','new_field_name':'bat_file','regex':'\"[^\"]+\.bat\"' }]
        self.assertEqual(added_fields,correct_fields)
        
        search = search + self.addfield2
        added_fields = search_object.getSearchAddedFields(search)
        correct_fields.append({ 'from_field_name':'command_line','new_field_name':'exe_file','regex':'\"[^\"]+\.exe\"' })
        self.assertEqual(added_fields,correct_fields)
         

    def test_getSearchJoinedFields(self):
        search = self.index1 + self.search1 + self.addfield1 + self.filterscript1 + self.joinfield1
        search_object = self.getSearchObject()
        joined_fields = search_object.getSearchJoinedFields(search)
        correct_fields = [{'new_field_name':'account','fields':'domain,username','delim':'\\'}]
        self.assertEqual(joined_fields,correct_fields)

        search = search + self.joinfield2
        joined_fields = search_object.getSearchJoinedFields(search)
        correct_fields.append({'new_field_name':'location','fields':'hostname,path','delim':'@'})
        self.assertEqual(joined_fields,correct_fields)

    def test_getSearchSplitField(self):
        search = self.index1 + self.search1 + self.addfield1 + self.fieldsplit1 + self.filterscript1 + self.joinfield1
        search_object = self.getSearchObject()
        split_fields = search_object.getSearchSplitField(search)
        correct_fields = [{'new_field_name':'userid','from_field_name':'username','array_item':'1','delim':'\\'}]
        self.assertEqual(split_fields,correct_fields)

        search = search + self.fieldsplit2
        correct_fields.append({'new_field_name':'domain','from_field_name':'email_address','array_item':'1','delim':'@'})
        split_fields = search_object.getSearchSplitField(search)
        self.assertEqual(split_fields,correct_fields)
        
    def test_addOutputToResults(self):
        search = self.index1 + self.search1 + self.addfield1 + self.addfield2
        test_result = {"_index": "test:carbonblack-000127", "_source": {"username": "CORPVAL\\a421176", "command_line": "random.exe \"C:\\temp\\1.exe\" \"C:\\temp\\1.bat\"", "path": "c:\\tools\\java\\jdk1.8.0_121\\bin\\java.exe", "hostname": "990351534"}}
        correct_result = {"_index": "test:carbonblack-000127", "_source": {"username": "CORPVAL\\a421176", "command_line": "random.exe \"C:\\temp\\1.exe\" \"C:\\temp\\1.bat\"", "path": "c:\\tools\\java\\jdk1.8.0_121\\bin\\java.exe", "hostname": "990351534", "exe_file":"C:\\temp\\1.exe", "bat_file":"C:\\temp\\1.bat"}}
        search_object = self.getSearchObject()
        alert_result = search_object.addNewFieldsToResult(test_result,search_object.getSearchAddedFields(search))       
        self.assertEqual(alert_result,correct_result)

    def test_getSearchJoinedFields(self):
        search = self.index1 + self.search1 + self.joinfield1 + self.joinfield2
        test_result = {"_index": "test:carbonblack-000127", "_source": {"username": "a421176", "domain":"CORPDOMAIN" ,"command_line": "random.exe \"C:\\temp\\1.exe\" \"C:\\temp\\1.bat\"", "path": "c:\\tools\\java\\jdk1.8.0_121\\bin\\java.exe", "hostname": "990351534"}}
        correct_result = {"_index": "test:carbonblack-000127", "_source": {"username": "a421176", "domain":"CORPDOMAIN", "account":"CORPDOMAIN\\a421176", "location":"990351534@c:\\tools\\java\\jdk1.8.0_121\\bin\\java.exe","command_line": "random.exe \"C:\\temp\\1.exe\" \"C:\\temp\\1.bat\"", "path": "c:\\tools\\java\\jdk1.8.0_121\\bin\\java.exe", "hostname": "990351534"}}
        search_object = self.getSearchObject()
        alert_result = search_object.addJoinedFieldToResult(test_result,search_object.getSearchJoinedFields(search))
        self.assertEqual(alert_result,correct_result)

    def test_addSplitFieldToResult(self):
        search = self.index1 + self.search1 + self.fieldsplit1 + self.fieldsplit2
        #fieldsplit1 = " --field-split:userid,username,1,__delim:'\\''"
        #fieldsplit2 = " --field-split:domain,email_address,1,__delim:'@'"
        test_result = {"_index": "test:carbonblack-000127", "_source": {"username": "CORPDOMAIN\\a421176", "email_address":"emailaddress@smtp.domain.com","command_line": "random.exe \"C:\\temp\\1.exe\" \"C:\\temp\\1.bat\"", "path": "c:\\tools\\java\\jdk1.8.0_121\\bin\\java.exe", "hostname": "990351534"}}
        correct_result = {"_index": "test:carbonblack-000127", "_source": {"username": "CORPDOMAIN\\a421176", "userid":"a421176","domain":"smtp.domain.com","email_address":"emailaddress@smtp.domain.com","command_line": "random.exe \"C:\\temp\\1.exe\" \"C:\\temp\\1.bat\"", "path": "c:\\tools\\java\\jdk1.8.0_121\\bin\\java.exe", "hostname": "990351534"}}
        search_object = self.getSearchObject()
        alert_result = search_object.addSplitFieldToResult(test_result,search_object.getSearchSplitField(search))
        self.assertEqual(alert_result,correct_result)

       
        
if __name__ == '__main__':
    unittest.main()
