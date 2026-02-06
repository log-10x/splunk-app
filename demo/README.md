

# 10x Splunk Demo
This manual is designed to allow you to test 10x decoding and search capabilities on your Splunk node using sample data.

This demo consists of two main parts:
1. Running a search on encoded data in your Splunk node, which decodes the data as part of it's execution.
2. Converting a plain Splunk search to a 10x search based on encoded data maps.

The easiest way to search on 10x encoded data is to install the 10x app, as the app bundles all the resources needed to convert plain searches into 10x compatible ones, as well as decoding capabilities.

If you don't wish to install the app, you can manually add the needed parts for this demo.

# Requirements
For running a decoding search job on encoded data, you're going to need to do the following things:
1. Create and populate a KV store collection.
-- For Splunk enterprise, this can be done either by editing configuration files, or via Rest API.
-- For Splunk cloud, this can be done by adding and using the [Splunk App for Lookup File Editing](https://splunkbase.splunk.com/app/1724)

2. Define a lookup on the KV store collection.
3. Add field extractions.
4. Create a search macro.

For converting a plain Splunk search into a 10x compatible one, you're going to need to do the following:

5. Generate a Splunk API token with the capability to run search jobs.
6. Run a Python script which communicates with your Splunk node using the API token.

Additional information about all the needed capabilities can be found in -
- [Define KV store collection via configuration files](https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usingconfigurationfiles/)
- [Manage KV store collection via Rest API](https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usetherestapitomanagekv/)
- [Define KV store collection in Splunk Web](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/DefineaKVStorelookupinSplunkWeb#KV_Store_collections)
- [Define KV store lookup in Splunk Web](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/DefineaKVStorelookupinSplunkWeb#Define_a_KV_Store_lookup)
- [Define KV store lookup via conf files](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/ConfigureKVstorelookups)
- [Define search macros](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Definesearchmacros)
- [Add field extractions](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Managesearch-timefieldextractions)
- [Generating API tokens](https://docs.splunk.com/Documentation/Splunk/latest/Security/CreateAuthTokens)

## Upload the demo log
The demo file is a 10x encoded version of a sample Spark log file taken from [Loghub](https://github.com/logpai/loghub/tree/master/Spark)

Download [tenx_encoded_spark_demo.log](/demo/tenx_encoded_spark_demo.log) and upload it to your Splunk node.
The easiest way is via the web interface:

1. Go to **Settings** > **Add Data**

![settings add data](/demo/images/Upload_file.png)

2. Select **Upload** files from my computer

![upload](/demo/images/Upload_file_2.png)

3. Either manually **Select** the file, or **Drag & Drop** it into the upload area, and click **Next** once the upload finishes

![select file](/demo/images/Upload_file_3.png)

4. When setting Source Type, change **Event Breaks** to be **Every line**, and click next.

![set sourcetype](/demo/images/Upload_file_4.png)

5. You'll be prompted to create a new _Source Type_. Name it **tenx_demo_sourcetype**, and enter a description if you wish

![save sourcetype](/demo/images/Upload_file_5.png)

6. There's no need to change any other thing, you can click on the green **Next**/**Review**/**Submit** all the way until the file gets uploaded

![complete upload](/demo/images/Upload_file_6.png)


## Create and populate KV collection
The easiest way to create and populate the KV store is via the **Splunk App for Lookup File Editing**, available [here](https://splunkbase.splunk.com/app/1724)
1. From the main app page, click the **Create a New Lookup** dropdown, and select **KV Store Lookup**

![Create KV store](/demo/images/New_KV_Store.png)

2. In the collection creation screen, provide the following -

Name - **tenx-demo-kv**

App - **Search & Reporting**

Fields - add the following fields: **pattern_hash**, **pattern**, **pattern_parts**, **part_0**, **pattern_terminator**, **timestamp_format**.
The type of all fields should be **String**
You may need to click the *Add another field* button to add all fields.
After you finish filling all the names, click the **Create Lookup** button.

![Set KV store fields](/demo/images/New_KV_Store_2.png)

3. After the collection is created, click the **Import** button, and chose the [tenx_templates_demo.csv](/demo/tenx_templates_demo.csv)

4. Once the upload is finished, it should look like this:

![Done creating](/demo/images/New_KV_Store_4.png)

*It's OK that some rows don't have values in all the columns.*

Alternatively, if you're using Splunk Enterprise, can't use the **Splunk App for Lookup File Editing** you can define the KV store either via [Rest API access](https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usetherestapitomanagekv/) or by [manually editing configuration files](https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usingconfigurationfiles/)

## Create a lookup on the KV collection
After you've got the KV collection set up, you need to define a lookup on it which is used the the 10x search:
1. From the **Search & Reporting** app, click on **Settings** > **Lookups**

![Create KV lookup](/demo/images/New_Lookup.png)

2. Click on **+ Add New** lookup definition

![Add new KV lookup](/demo/images/New_Lookup_2.png)

3. In the lookup creation screen, provide the following -

*Name* - **tenx-kv-lookup**

*Collection Name* - **tenx-demo-kv**

*Supported Fields* - provide the following list:

> _key,pattern_hash,pattern,pattern_parts,part_0,pattern_terminator,timestamp_format

After you finish filling everything, click the **Save** button

![Done create KV lookup](/demo/images/New_Lookup_3.png)

**Optionally** - if you want to have the lookup available for other apps in your node, so you can perform 10x searches in them as well, you'll need to:
1. Go to the permissions settings of the lookup you just created

![KV lookup permissions](/demo/images/New_Lookup_4.png)

2. Give everyone **read** access to the lookup

![KV lookup read permissions](/demo/images/Read_permissions.png)

3. Click **Save**

## Add a field extraction
In order for the KV lookup to have an input field to use, we need to define a search time field extraction on the demo file:

1. From the **Search & Reporting** app, click on **Settings** > **Fields**

![Create field extraction](/demo/images/Field_Extract.png)

2. Click on **+ Add New** field extractions

![New field extraction](/demo/images/Field_Extract_2.png)

3. In the creation screen, provide the following -

*Name* - **tenx_demo_fields**

*Apply to* - set to **Source**, and provide the name of the demo file **tenx_encoded_spark_demo.log**

*Type* - provide the following extraction regex:
> ^(?<tenx_hash>\$?\w+)( (?<tenx_var_0>[^\s]+)( (?<tenx_vars>.*))?)?

After you finish filling everything, click the **Save** button

![Done creating field extraction](/demo/images/Field_Extract_3.png)

**Optionally** - if you want to have the field extraction available for other apps in your node, so you can perform 10x searches in them as well, you'll need to:

1. Go to the permissions settings of the field extraction you just created

![Field extraction permissions](/demo/images/Field_Extract_4.png)

2. Give everyone **read** access to the field extraction

![Field extraction read permissions](/demo/images/Read_permissions.png)

3. Click **Save**


You can **verify** the field extraction works by:
1. Go to the **Search & Reporting** app
2. Perform a search for **source="tenx_encoded_spark_demo.log"** with a time of **All time**
3. Check that events have the **tenx_hash**, **tenx_var_0** and **tenx_vars** fields.
4. **Note** - some events might not have the **tenx_var_0** or **tenx_vars** fields, but all should have the **tenx_hash** field

![Verification search](/demo/images/Verification_Search.png)

## Add 10x decode macro
The last part of decoding the 10x encoded data is to connect the encoded data, extracted 10x fields, and KV lookup with a macro.

1. From the **Search & Reporting** app, click on **Settings** > **Advanced search**

![Create macro](/demo/images/Macro.png)

2. Click on **+ Add New** search macros

![New macro](/demo/images/Macro_2.png)

3. In the macro creation screen, provide the following -

*Name* - **tenx-decode**

*Definition* - provide the following definition:

> makemv tenx_vars | lookup tenx-kv-lookup pattern_hash AS tenx_hash OUTPUT part_0 AS tenx_part_0, pattern_parts AS tenx_log_parts, pattern_terminator AS tenx_log_term, timestamp_format AS tenx_ts_f | makemv tenx_log_parts delim="@@" | eval _raw=if(isnull(tenx_log_term), _raw, if(tenx_ts_f == "", if(isnull(tenx_var_0), tenx_log_term, mvjoin(mvappend(tenx_part_0, tenx_var_0, mvzip(tenx_log_parts,tenx_vars,""), tenx_log_term),"")), replace(mvjoin(mvappend(mvzip(tenx_log_parts,tenx_vars,""), tenx_log_term),""), "\_\_TENX\_TS\_\_", strftime(tenx_var_0 / 1000, tenx_ts_f))))

Other macro fields aren't needed, after you finish filling everything, click the **Save** button

![Done create macro](/demo/images/Macro_3.png)

**Optionally** - if you want to have the macro available for other apps in your node, so you can perform 10x searches in them as well, you'll need to:

1. Go to the permissions settings of the macro you just created

![Macro permissions](/demo/images/Macro_4.png)

2. Give everyone **read** access to the field extraction

![Macro read permissions](/demo/images/Read_permissions.png)

3. Click **Save**

## Running a verification search
Now that the macro is setup, we can pipe any search into it and it will decode the data.
We can simply run the same search from before, but pipe it into the macro:
> source="tenx_encoded_spark_demo.log" | \`tenx-decode\`

![Verification search](/demo/images/Verification_Search_2.png)

## Generating an API token
In order to run the Python script which generates a 10x search from a plain search, we need to generate an API token allowing the script to communicate with the Splunk node:

1. From the **Search & Reporting** app, click on **Settings** > **Tokens**

![Create token](/demo/images/Generate_Token.png)

2. Click on **New Token**

![Create new token](/demo/images/Generate_Token_2.png)

3. In the creation screen, provide the following:

*User* - your **username**

*Audience* - **tenx-api** (or any name reminding you what this token is for)

*Expiration* - Either leave it blank, or something that'll expire when you want it to, like **+30d** for 30 days

![Done creating token](/demo/images/Generate_Token_3.png)

4. Click **Create**, and be sure to **copy the token** generated, as it's the **only** time it'll be displayed.

## Running the Python script
Once you have your token, running the python script converting a plain search to a 10x search is pretty simple -
> python tenx_search.py --host \<splunk hostname> --key \<api token> --user \<your username> --search \<search string>

For example, running the following:
> python tenx_search.py --host https://localhost:8089 --key eyJraWQiOiJz... --user splunk_user --search "source=tenx_encoded_spark_demo.log slf4j"

Will yield the following 10x search:
> | search source=tenx_encoded_spark_demo.log ((slf4j) OR (tenx_hash IN (esszmA8cXJL,fSh3gng9Pq5,\$ifXGk6Kc6CS,kGeu7kVZHuz,\$bcj4ljY0Wn,\$fghIDle3lJk,dmwlbqMGyGL))) | \`tenx-decode\` | extract

Running this search in splunk will return all the events with the word *slf4j* in them, in their decoded form.

![Decoded search](/demo/images/Decoded_Search.png)
