use std::{collections::{HashMap, HashSet}, fs::{self, File, OpenOptions}, io::{self, Cursor, Read, Seek}, path::Path, process::Command};

use octocrab::models::issues::Issue;
use regex::Regex;
use colored::Colorize;
use ini::Ini;
use zip::{read::ZipFile, result::ZipError};
use utf16string::WString;
use tempdir::TempDir;
use serde::Deserialize;
use clap::Parser;
use directories::BaseDirs;
use itertools::Itertools;



struct LogInformation
{
    appxversion: Option<String>,
    parse_error: bool,
    evaluation_result: Vec<MatchResult>
}

impl Default for LogInformation {
    fn default() -> LogInformation {
        LogInformation {
            appxversion: None,
            parse_error: false,
            evaluation_result: Vec::new()
        }
    }
}

#[derive(Deserialize, PartialEq, Debug)]
struct Match
{
    contains: Option<String>,
    regex: Option<String>,
    not: Option<Box<RuleString>>
}

#[derive(Clone,)]
struct MatchResult
{
    name: String,
    captures: HashMap<String, String>
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(untagged)]
enum RuleString
{
    BasicString(String),
    Match(Match)
}

#[derive(Deserialize, PartialEq, Debug)]
struct CaptureList
{
    field1: Option<String>,
    field2: Option<String>,
    field3: Option<String>,
    field4: Option<String>,
    field5: Option<String>,
    field6: Option<String>,
    field7: Option<String>,
    field8: Option<String>,
    field9: Option<String>,
    field10: Option<String>,
    event: Option<String>
}

#[derive(Deserialize, PartialEq, Debug)]
struct CaptureRule
{
    name: String,
    capture: CaptureList
}


#[derive(Deserialize, PartialEq, Debug)]
#[serde(untagged)]
enum SetRule
{
    BasicString(String),
    Capture(CaptureRule)
}

#[derive(Deserialize, PartialEq, Debug)]
struct LoglineRule
{
    provider: Option<RuleString>,
    task: Option<RuleString>,
    event: Option<RuleString>,
    field1: Option<RuleString>,
    field2: Option<RuleString>,
    field3: Option<RuleString>,
    field4: Option<RuleString>,
    field5: Option<RuleString>,
    field6: Option<RuleString>,
    field7: Option<RuleString>,
    field8: Option<RuleString>,
    field9: Option<RuleString>,
    field10: Option<RuleString>,
}


#[derive(Deserialize, PartialEq, Debug)]
struct Rule
{
    logline: Option<LoglineRule>,
    set: Option<SetRule>,
    oneshot: Option<bool>,
}

#[derive(Deserialize, PartialEq, Debug)]
struct Foreach
{
    var: String,
    user_message: Option<String>,
    debug_message: Option<String>
}

#[derive(Deserialize, PartialEq, Debug)]
struct ConditionEval
{
    and: Option<Vec<Condition>>,
    or: Option<Vec<Condition>>,
    not: Option<Box<Condition>>
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(untagged)]
enum Condition 
{
    BasicString(String),
    Eval(ConditionEval)
}

#[derive(Deserialize, PartialEq, Debug)]
struct When
{
    condition: Condition,
    user_message: Option<String>,
    debug_message: Option<String>,
    tag: Option<String>,
    skip_similar_issues: Option<bool>
}

#[derive(Deserialize, PartialEq, Debug)]
struct Action
{
    foreach: Option<Foreach>,
    when: Option<When>
}

#[derive(Deserialize, PartialEq, Debug)]
struct LogsRules
{
    missing_logs_message: String,
    missing_logs_etl_message: String,
    skip_tags: Vec<String>,
    missing_logs_add_tags: Vec<String>,
}

#[derive(Deserialize, PartialEq, Debug)]
struct TagsRules
{
    tags: Vec<TagRule>,
    ignore: Vec<String>
}

#[derive(Deserialize, PartialEq, Debug)]
struct TagRule
{
    contains: String,
    tag: String
}

#[derive(Deserialize, PartialEq, Debug)]
struct OptionalComponentRule
{
    name: String,
    set: String
}

#[derive(Deserialize, PartialEq, Debug)]
struct Config
{
    rules: Vec<Rule>,
    actions: Vec<Action>,
    wpa_profile: String,
    logs_rules: LogsRules,
    tags_rules: TagsRules,
    optional_component_rules: Vec<OptionalComponentRule>
}

#[derive(Debug)]
struct GithubIssueActions
{
    user_messages: String,
    debug_messages: String,
    tags: Vec<String>,
    show_similar_issues: bool,
}

async fn get_logs_from_issue_description(issue:& Issue) -> Vec<String>
{
    print!("Fetching logs for issue '{}'\n", issue.title);

    return extract_log_url_from_body(issue.body.as_deref().unwrap_or(""));
}

async fn get_logs_from_issue_comments(issue: &Issue) -> Vec<String>
{
    let comments = octocrab::instance()
    .issues("microsoft", "WSL")
    .list_comments(issue.number)
    .send().await;

    if let Ok(page) = comments 
    {
        for e in page
        {
            if e.user == issue.user
            {
                let log_url = extract_log_url_from_body(&e.body.unwrap_or_default());
                if !log_url.is_empty()
                {
                    print!("Found logs from comment: {}\n", e.html_url);
                    return log_url;
                }
            }
        }
    }

    print!("{}", "No logs found in issue comments".red());
    return Vec::new();
}


fn extract_log_url_from_body(body: &str) -> Vec<String>
{
    let re = Regex::new(r"https?:\/\/[^\s^\)]+").unwrap();

    re.find_iter(&body).map(|e|e.as_str().to_string()).filter(|e|e.ends_with(".zip")).collect()
}

async fn download_logs(url: &String) -> File
{
    let response = reqwest::get(url).await.expect("No response received");

    match response.error_for_status()
    {
        Ok(res) => {
        let fname = url.split('/').last().unwrap();
    
        print!("Download logs to: {}\n", fname);

        let mut target= OpenOptions::new().read(true).write(true).create(true).open(fname).unwrap();
        let mut content =  Cursor::new(res.bytes().await.unwrap());

        std::io::copy(&mut content, &mut target).unwrap();
        target.rewind().unwrap();

        return target

        },
        Err(_err) => panic!("HTTP error when downloading logs")
    }
}

fn decode_powershell_output(file: ZipFile) -> String
{
    let mut input: Vec<u8> = file.bytes().map(|e|e.unwrap()).collect();

    let mut mabye_utf16le = false;
    
    // Look for a BOM header
    if input.len() >= 2 && input[0] == 255 && input[1] == 254
    {
        mabye_utf16le = true;
        input = input.iter().skip(2).copied().collect();
    }

    // If the second byte is zero, this is most likely utf16 le

    if input.len() >= 2 && input[1] == 0
    {
        mabye_utf16le = true;
    }

    return if mabye_utf16le
    {
        match WString::from_utf16le(input.clone()).and_then(|e| Ok(e.to_utf8()))
        {
            Ok(str) => str,
            Err(_) => std::str::from_utf8(input.as_slice()).unwrap().to_string()
        }
    }
    else
    {
        std::str::from_utf8(input.as_slice()).unwrap().to_string()
    }
}

fn process_logs(file: & mut File, config: &Config, extract_xls: Option<String>, actions: &mut GithubIssueActions) -> LogInformation
{
    let mut log_info = LogInformation::default();

    let mut archive = zip::ZipArchive::new(file).unwrap();

    // Some zips have '\' separator and somes have '/'

    let path = archive.file_names().next().unwrap().to_string();
    let sep = if path.contains("/") 
    {
        "/"
    }
    else
    {
        if !path.contains("\\")
        {
            add_message(("Failed to parse logs. Unexpected file: ".to_owned() + &path).as_str(), &HashMap::new(), &mut actions.user_messages);
            return log_info;
        }

        "\\"
    };

    let root = path.split(sep).next().unwrap().to_string();
    print!("Archive root: {}\n", root);

    {
        let name = root.to_owned() + sep  + ".wslconfig";
        let wslconfig = archive.by_name(&name);


        if wslconfig.is_ok()
        {
            add_message(".wslconfig found", &HashMap::new(), &mut actions.debug_messages);

            let content = decode_powershell_output(wslconfig.unwrap());
        
            process_wslconfig(content, actions);
        }
    }

    {
        process_appxpackage( archive.by_name((root.to_owned() + sep + "appxpackage.txt").as_str()),  &mut log_info, actions);
    }

    {
        process_optional_components(archive.by_name((root.to_owned() + sep + "optional-components.txt").as_str()), &mut log_info, actions, &config.optional_component_rules)
    }

    {
        let tmp_dir = TempDir::new("wti-logs").unwrap();
        archive.extract(tmp_dir.path()).unwrap();
        
        let etl_path = tmp_dir.path().join(root).join("logs.etl");
        if !etl_path.exists()
        {
            add_message("No logs.etl found in archive.", &HashMap::new(), &mut actions.debug_messages);
            add_message(&config.logs_rules.missing_logs_etl_message, &HashMap::new(), &mut actions.user_messages);

            for e in config.logs_rules.missing_logs_add_tags.as_slice()
            {
                actions.tags.push(e.to_string());
            }

            log_info.parse_error = true;
        }
        else 
        {
            let etl_result = process_etl(&etl_path, &config.rules, &config.wpa_profile, extract_xls);

            log_info.parse_error = etl_result.is_none();
            log_info.evaluation_result.append(&mut etl_result.unwrap_or_default());
        }
    }

    log_info
}


fn process_etl(etl: &Path, rules: &Vec<Rule>, wpa_profile: &String, extract_xls: Option<String>) -> Option<Vec<MatchResult>>
{
    
    let output_dir = TempDir::new("wti-logs-xls").unwrap();
    let output_path =   output_dir.path().to_str().unwrap();

    let etl_path = etl.to_str().unwrap();
    print!("Extracting logs from: {}\n", etl_path);

    // -tle is required to process .etl when events are lost
    let args = vec!["-tle",
    "-tti",
     "-i",
    etl_path,
    "-profile",
    wpa_profile.as_str(),
    "-outputfolder",
    output_path];

    let result = Command::new("C:\\Program Files (x86)\\Windows Kits\\10\\Windows Performance Toolkit\\wpaexporter.exe").args(args.as_slice()).output().expect("Failed to spwn wpa");

    if !result.status.success()
    {
        print!("wpaexporter failed. Args: {} stdout: {}, stderr: {}\n", args.join(" "), String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
        return None
    }


    let files: Vec<String> = fs::read_dir(output_path).unwrap().map(|e|e.unwrap()).filter(|e| e.file_type().unwrap().is_file()).map(|e|e.file_name().to_str().unwrap().to_string()).filter(|e|e.ends_with("(1).csv")).collect();
    if files.is_empty()
    {
        print!("{} {}", "No xls files found in directory: \n".red(), output_path);
        return None
    }
    else if files.len() > 1
    {
        print!("{} {}, {}", "More than 1 xls files found in directory: \n".red(), output_path, files.join(","));
        return None
    }

    let xls_path = output_path.to_owned() + "\\" + files.first().unwrap();

    print!("Extracted xls logs to: {}\n", xls_path);

    if extract_xls.is_some()
    {
        let target = extract_xls.unwrap();
        print!("Copied xls logs to: {}\n", target.bold());

        fs::copy(&xls_path, target).expect("Failed to copy xls");
    }

    return Some(read_logs_xls(&xls_path, rules));
}

fn rule_match(value: &str, match_rule: &Match) -> bool
{
    if match_rule.contains.is_some()
    {
        return value.contains(match_rule.contains.as_ref().unwrap());
    }
    else if match_rule.regex.is_some()
    {
        // TODO: This is very slow
        return Regex::new(match_rule.regex.as_ref().unwrap()).unwrap().is_match(value)
    }
    else if match_rule.not.is_some()
    {
        return !string_match(Some(&value.to_string()), match_rule.not.as_ref().unwrap())
    }

    print!("Found invalid match rule: {:?}", match_rule);
    panic!("invalid match rule");
}

fn string_match(value: Option<&String>, rule: &RuleString) -> bool
{
    if value.is_none()
    {
        return false;
    }

    return match rule {
        RuleString::BasicString(e) => e == value.unwrap(),
        RuleString::Match(e) => rule_match(value.unwrap(), e)
    }
}

fn evaluate_capture(captures: &CaptureList, fields: &HashMap<String, String>) -> HashMap<String, String>
{
    let mut result: HashMap<String, String> = HashMap::new();

    if captures.field1.is_some() && fields.contains_key("Field 1")
    {
        result.insert(captures.field1.as_ref().unwrap().to_string(), fields["Field 1"].to_string());
    }
    if captures.field2.is_some() && fields.contains_key("Field 2")
    {
        result.insert(captures.field2.as_ref().unwrap().to_string(), fields["Field 2"].to_string());
    }
    if captures.field3.is_some() && fields.contains_key("Field 3")
    {
        result.insert(captures.field3.as_ref().unwrap().to_string(), fields["Field 3"].to_string());
    }
    if captures.field4.is_some() && fields.contains_key("Field 4")
    {
        result.insert(captures.field4.as_ref().unwrap().to_string(), fields["Field 4"].to_string());
    }
    if captures.field5.is_some() && fields.contains_key("Field 5")
    {
        result.insert(captures.field5.as_ref().unwrap().to_string(), fields["Field 5"].to_string());
    }
    if captures.field6.is_some() && fields.contains_key("Field 6")
    {
        result.insert(captures.field6.as_ref().unwrap().to_string(), fields["Field 6"].to_string());
    }
    if captures.field7.is_some() && fields.contains_key("Field 7")
    {
        result.insert(captures.field7.as_ref().unwrap().to_string(), fields["Field 7"].to_string());
    }
    if captures.field8.is_some() && fields.contains_key("Field 8")
    {
        result.insert(captures.field8.as_ref().unwrap().to_string(), fields["Field 8"].to_string());
    }
    if captures.field9.is_some() && fields.contains_key("Field 9")
    {
        result.insert(captures.field9.as_ref().unwrap().to_string(), fields["Field 9"].to_string());
    }
    if captures.field10.is_some() && fields.contains_key("Field 10")
    {
        result.insert(captures.field10.as_ref().unwrap().to_string(), fields["Field 10"].to_string());
    }

    if captures.event.is_some() && fields.contains_key("Event Name")
    {
        result.insert(captures.event.as_ref().unwrap().to_string(), fields["Event Name"].to_string());
    }

    return result;
}

fn evaluate_set_capture(rule: &SetRule, fields: &HashMap<String, String>) -> MatchResult
{
    match rule {
        SetRule::BasicString(e) => MatchResult{name: e.to_string(), captures: HashMap::new()},
        SetRule::Capture(e) => MatchResult{name: e.name.to_string(), captures: evaluate_capture(&e.capture, fields)}
    }
}

fn evaluate_rule(rule: &Rule, fields: &HashMap<String, String>) -> Option<MatchResult>
{
    if rule.logline.is_none()
    {
        return None;
    }

    let filters = rule.logline.as_ref().unwrap();

    if filters.provider.is_some() && !string_match(fields.get("Provider Name"), &filters.provider.as_ref().unwrap())
    {
        return None;
    }

    if filters.event.is_some() && !string_match(fields.get("Event Name"), &filters.event.as_ref().unwrap())
    {
        return None;
    }

    if filters.task.is_some() && !string_match(fields.get("Task Name"), &filters.task.as_ref().unwrap())
    {
        return None;
    }

    if filters.field1.is_some() && !string_match(fields.get("Field 1"), &filters.field1.as_ref().unwrap())
    {
        return None;
    }

    if filters.field2.is_some() && !string_match(fields.get("Field 2"), &filters.field2.as_ref().unwrap())
    {
        return None;
    }

    if filters.field3.is_some() && !string_match(fields.get("Field 3"), &filters.field3.as_ref().unwrap())
    {
        return None;
    }

    if filters.field4.is_some() && !string_match(fields.get("Field 4"), &filters.field4.as_ref().unwrap())
    {
        return None;
    }

    if filters.field5.is_some() && !string_match(fields.get("Field 5"), &filters.field5.as_ref().unwrap())
    {
        return None;
    }

    if filters.field6.is_some() && !string_match(fields.get("Field 6"), &filters.field6.as_ref().unwrap())
    {
        return None;
    }

    if filters.field7.is_some() && !string_match(fields.get("Field 7"), &filters.field7.as_ref().unwrap())
    {
        return None;
    }

    if filters.field8.is_some() && !string_match(fields.get("Field 8"), &filters.field8.as_ref().unwrap())
    {
        return None;
    }

    if filters.field9.is_some() && !string_match(fields.get("Field 9"), &filters.field9.as_ref().unwrap())
    {
        return None;
    }

    if filters.field10.is_some() && !string_match(fields.get("Field 10"), &filters.field10.as_ref().unwrap())
    {
        return None;
    }

    if rule.set.is_some()
    {
        return Some(evaluate_set_capture(rule.set.as_ref().unwrap(), fields));
    }
    else 
    {
        return None;
    }

}

fn process_logline(rules: &Vec<Rule>, fields: &HashMap<String, String>, oneshot_rules: &mut HashSet<usize>) -> Vec<MatchResult>
{
    let mut results : Vec<MatchResult> = Vec::new();
    for (index, rule) in rules.iter().enumerate()
    {
        if !oneshot_rules.contains(&index)
        {
            if let Some(result) = evaluate_rule(rule, fields)
            {
                results.push(result);

                if rule.oneshot.unwrap_or(false)
                {
                    oneshot_rules.insert(index);
                }
            }
        }
    }

    return results
}


fn read_logs_xls(path: &str, rules: &Vec<Rule>) -> Vec<MatchResult>
{
    let mut file = csv::ReaderBuilder::new().from_path(path).unwrap();
    let headers = file.headers().unwrap().iter().map(|e|e.to_string()).collect::<Vec<String>>();

    let fields_of_interest = vec!["Provider Name", "Task Name", "Event Name", "Field 1", "Field 2", "Field 3", "Field 4", "Field 5", "Field 6", "Field 7", "Field 8", "Field 9", "Field 10"];

    let indexes = fields_of_interest.iter().map(|field| (field, headers.iter().position(|e|e == field))).collect::<HashMap<_, _>>();
    
    let mut results = Vec::new();
    let mut oneshot_rules: HashSet<usize> =  HashSet::new();
    for row in file.records()
    {   
        let mut fields = HashMap::<String, String>::new();

        let entries = row.unwrap();
        for e in &indexes
        {
            if indexes[e.0].is_some()
            {
                fields.insert(e.0.to_string(), entries[e.1.unwrap()].to_string());
            }
        }

        results.append(&mut process_logline(&rules, &fields, &mut oneshot_rules));
    }

    return results

}

fn process_memory_string(content: String, actions: &mut GithubIssueActions)
{
    let comment = content.find("#");

    let cleaned_string = 
    if comment.is_some()
    {
        &content[0..comment.unwrap()]
    }
    else
    {
        &content
    };

    use byte_unit::*;
    match Byte::parse_str(cleaned_string, true)
    {
        Ok(result) => {
            if result.as_u64() < Byte::parse_str("1000MB", true).unwrap().as_u64()
            {
                add_message(&format!("\tLow value for wsl2.memory: '{result}'"), &HashMap::new(), &mut actions.debug_messages);
            }
        }
        Err(_err) =>  {
            add_message(&format!("\tFailed to parse wsl2.memory: '{content}'"), &HashMap::new(), &mut actions.debug_messages);
        }
    }
}

fn process_wslconfig(content: String, actions: &mut GithubIssueActions)
{
    match Ini::load_from_str(&content)
    {
        Ok(config) => 
        {
            match config.get_from(Some("wsl2"), "kernelCommandLine") {
                Some(value) => {add_message(&format!("\tCustom kernel command line found: '{value}'"), &HashMap::new(), &mut actions.debug_messages);}
                None => ()
            }

            match config.get_from(Some("wsl2"), "memory") {
                Some(value) => process_memory_string(value.to_string(), actions),
                None => ()
            }

            match config.get_from(Some("wsl2"), "kernel") {
                Some(value) => {add_message(&format!("\tCustom kernel found: '{value}'"), &HashMap::new(), &mut actions.debug_messages);}
                None => ()
            }

        }

        Err(err) => add_message(("Failed to parse .wslconfig: ".to_owned() + &err.msg + &content).as_str(), &mut HashMap::new(), &mut actions.debug_messages)
    }
}

fn process_appxpackage(file: Result<zip::read::ZipFile, ZipError>, result: &mut LogInformation, actions: &mut GithubIssueActions)
{
    if file.is_err()
    {
        add_message("appxpackage.txt not found", &HashMap::new(), &mut actions.debug_messages);
        return;
    }

    let mut content =  decode_powershell_output(file.unwrap());

    if !content.contains("MicrosoftCorporationII.WindowsSubsystemForLinux")
    {
        add_message("Appx package is not installed", &HashMap::new(), &mut actions.debug_messages);
        return;
    }

    content = content.replace("\r", "");

    let version = content.split("\n").filter(|e| e.starts_with("Version ")).next();
    if version.is_none()
    {
        add_message(("Failed to parse appxpackages.txt: ".to_owned() + &content).as_str(), &HashMap::new(), &mut actions.debug_messages);
        return;
    }

    let version_split: Vec<&str> = version.unwrap().split(":").collect();
    if version_split.len() < 2
    {
        add_message(("Failed to parse version string from: appxpackages.txt: ".to_owned() + &version.unwrap()).as_str(), &HashMap::new(), &mut actions.debug_messages);
        return;
    }

    result.appxversion = Some(version_split[1].trim().to_string());

    add_message(("Detected appx version: ".to_owned() +  result.appxversion.as_ref().unwrap()).as_str(), &HashMap::new(), &mut actions.debug_messages);
}

fn process_optional_components(file: Result<zip::read::ZipFile, ZipError>, result: &mut LogInformation, actions: &mut GithubIssueActions, rules: &Vec<OptionalComponentRule>)
{
    if file.is_err()
    {
        add_message("optional-components.txt not found", &HashMap::new(), &mut actions.debug_messages);
        return;
    }

    let content = decode_powershell_output(file.unwrap()).replace("\r", "");

    let mut name: Option<String> = None;

    for e in content.split("\n")
    {
        if ! e.contains(":")
        {
            continue;
        }

        let parts: Vec<&str> = e.split(":").collect();
        if parts.len() != 2
        {
            add_message(("Unexpected format in optional-component.txt: ".to_owned() + e).as_str(), &HashMap::new(), &mut actions.debug_messages);
            return;
        }

        let field = parts[0].trim().to_lowercase();

        if field == "featurename"
        {
            name = Some(parts[1].trim().to_lowercase().to_string());
        }
        else if field == "state"
        {
            let state = parts[1].trim().to_lowercase();

            if state == "enabled"
            {
                let rule = rules.iter().find(|r|r.name.to_lowercase() == name.as_ref().unwrap_or(&"".to_string()).to_string());
                if rule.is_some()
                {
                    result.evaluation_result.push(MatchResult{name: rule.as_ref().unwrap().set.to_string(), captures: HashMap::new()});
                }
            }
            else if state != "disabled" && state != "disabledwithpayloadremoved"
            {
                add_message(("Unexpected format in optional-component.txt: ".to_owned() + e).as_str(), &HashMap::new(), &mut actions.debug_messages);
                return;
            }
        }
    }

}


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Issue number
    #[arg(short, long)]
    issue: Option<u64>,

    #[arg(long)]
    comment: Option<u64>,

    #[clap(long, short)]
    export_xls: Option<String>,

    #[clap(long)]
    input_xls: Option<String>,

    #[clap(long, short)]
    debug_rules: bool,

    #[clap(long)]
    github_token: Option<String>,

    #[clap(long)]
    ignore_tags: bool,

    #[clap(long)]
    default_message_stdin: bool,

    #[clap(long)]
    config: Option<String>,

    #[clap(long)]
    comments: bool,

    #[clap(long)]
    previous_issue_body: Option<String>
}

fn add_message(message: &str, fields: &HashMap<String, String>, target: &mut String)
{
    let mut formatted_message: String = message.to_string();

    for var in fields
    {
        let from = "$".to_string() + var.0;
        formatted_message = formatted_message.replace(&from, var.1).to_string();
    }

    if !target.is_empty()
    {
        *target += "\n";
    }

    *target += &formatted_message;
}

fn evaluate_foreach(results: &LogInformation, foreach: &Foreach, output: &mut GithubIssueActions)
{
    for e in results.evaluation_result.as_slice()
    {
        if e.name == foreach.var
        {
            if foreach.user_message.is_some()
            {
                add_message(&foreach.user_message.as_ref().unwrap(), &e.captures, &mut output.user_messages);
            }
            
            if foreach.debug_message.is_some()
            {
                add_message(&foreach.debug_message.as_ref().unwrap(), &e.captures, &mut output.debug_messages);
            }
        }
    }
}

fn evaluate_expression(result: &LogInformation, exp: &ConditionEval, matches: &mut Vec<MatchResult>) -> bool
{
    if exp.and.is_some()
    {
        return exp.and.as_ref().unwrap().iter().all(|e| evaluate_condition(result, &e, matches))
    }
    else if exp.or.is_some()
    {
        return exp.or.as_ref().unwrap().into_iter().any(|e| evaluate_condition(result, &e, matches))
    }
    else if exp.not.is_some()
    {
        return !evaluate_condition(result, exp.not.as_ref().unwrap(), matches)
    }
    else 
    {
        panic!("Invalid condition");
    }
}

fn evaluate_condition(result: &LogInformation, condition: &Condition, matches:&mut Vec<MatchResult>) -> bool
{
    return match condition
    {
        Condition::BasicString(e) => 
        {
            let mut found = result.evaluation_result.iter().filter(|entry| entry.name == *e).map(|entry|(*entry).clone()).collect::<Vec<MatchResult>>();

            let matched = !found.is_empty();
            matches.append(&mut found);
            
            matched
        }
        Condition::Eval(e) => evaluate_expression(result, e, matches)
    }
}

fn evaluate_when(result: &LogInformation, when: &When, output: &mut GithubIssueActions)
{
    let mut matches = Vec::new();
    if evaluate_condition(result, &when.condition, &mut matches)
    {
        let mut fields: HashMap<String, String> = HashMap::new();

        for e in matches
        {
            for (key, value) in e.captures
            {
                fields.insert(key, value);

            }
        }


        if when.user_message.is_some()
        {
            add_message(&when.user_message.as_ref().unwrap(), &fields, &mut output.user_messages);
        }

        if when.debug_message.is_some()
        {
            add_message(&when.debug_message.as_ref().unwrap(), &fields, &mut output.debug_messages);
        }

        if when.skip_similar_issues.unwrap_or(false)
        {
            output.show_similar_issues = false;
        }

        if when.tag.is_some() && !output.tags.contains(when.tag.as_ref().unwrap())
        {
            output.tags.push(when.tag.as_ref().unwrap().to_string());
        }
    }
}

fn apply_actions(results: &LogInformation, actions: &Vec<Action>, output: &mut GithubIssueActions)
{
    if results.parse_error
    {
        add_message("Error while parsing the logs. See action page for details", &HashMap::new(), &mut output.debug_messages);
        return;
    }

    for action in actions
    {
        if action.foreach.is_some()
        {
            evaluate_foreach(results, action.foreach.as_ref().unwrap(), output)
        }
        else if action.when.is_some()
        {
            evaluate_when(results, action.when.as_ref().unwrap(), output)
        }
    }
}

async fn update_issue(github: &mut octocrab::Octocrab, issue: u64, message: &String, debug_messages: &String, tags: &Vec<String>)
{
    let mut comment: String = message.to_string();

    if !debug_messages.is_empty()
    {
        let escaped = html_escape::encode_text(debug_messages);
        comment += format!("\n<details>\n\n<summary>Diagnostic information</summary>\n\n```\n{escaped}\n```\n</details>").as_ref();
    }

    if !comment.is_empty()
    {
        github.issues("microsoft", "WSL").create_comment(issue, comment).await.expect("Failed to comment issue");
    }

    if !tags.is_empty()
    {
        github.issues("microsoft", "WSL").add_labels(issue, tags).await.expect("Failed to add tags");
    }
}

fn get_default_config_path() -> String
{
    return BaseDirs::new().unwrap().config_dir().to_str().unwrap().to_string() + "\\wti\\config.yml";
}

fn process_tags(text:& String, rules: &TagsRules, actions: &mut GithubIssueActions)
{
    // users will sometimes reply to bot messages. Skip quotation blocks when looking for tag strings
    let mut cleaned_text = text.split("\n").collect::<Vec<&str>>().iter().filter(|e|!e.trim().starts_with('>')).map(|e|e.to_lowercase().to_string()).collect::<Vec<String>>().as_slice().join("\n");

    // Remove all the 'ignored' strings from the message
    for e in &rules.ignore
    {
        cleaned_text = cleaned_text.replace(e, "");
    }

    for e in &rules.tags
    {
        if cleaned_text.contains(&e.contains)
        {
            actions.tags.push(e.tag.to_string());

            add_message(format!("Found '{}', adding tag '{}'", e.contains, e.tag).as_str(), &HashMap::new(), &mut actions.debug_messages);
        }
    }
}

#[tokio::main]
async fn main()
{
    let args = Args::parse();

    let mut github = if args.github_token.is_some()
    {
        octocrab::OctocrabBuilder::new().personal_token(args.github_token.as_ref().unwrap().to_string()).build().unwrap()
    }
    else
    {
        octocrab::OctocrabBuilder::new().build().unwrap()
    };

    let mut previous_issue_body: Option<String> = None;

    if args.previous_issue_body.is_some()
    {
        if args.comment.is_some()
        {
            panic!("Can't pass --comment and --previous-issue-body at the same time.");
        }

        previous_issue_body = Some(fs::read_to_string(args.previous_issue_body.unwrap()).unwrap());
    }


    let config_path = args.config.unwrap_or_else(||get_default_config_path());
    print!("Reading config from: {config_path}\n");

    let file = File::open(config_path).unwrap();
    let reader  = serde_yaml::Deserializer::from_reader(file);

    let config = Config::deserialize(reader).unwrap();

    let mut actions= GithubIssueActions{tags: Vec::new(), user_messages: String::new(), debug_messages: String::new(), show_similar_issues: true};

    let results: Option<LogInformation> = if args.issue.is_some()
    {
        let issue_number = args.issue.unwrap();
        let issue = github.issues("microsoft", "WSL").get(issue_number).await.expect("Failed to fetch issue");

        if args.comment.is_none() && !args.ignore_tags && issue.labels.iter().any(|e| config.logs_rules.skip_tags.contains(&e.name))
        {
            print!("Skipping issues because of its tags: {:?}\n", issue.labels.iter().map(|e|e.name.to_string()).collect::<Vec<String>>());
            None
        }
        else
        {
            let mut log_urls: Vec<String>;
            
            if args.comment.is_some()
            {
                let comment = github.issues("microsoft", "WSL").get_comment(args.comment.unwrap().into()).await.expect("Failed to read issue comment");
                if comment.user.id != issue.user.id
                {
                    print!("Issue author ({}) doesn't match comment author ({}), skipping\n", issue.user.login, comment.user.login);
                    return;
                }

                process_tags(&comment.body.as_ref().unwrap_or(&"".to_owned()), &config.tags_rules, &mut actions);

                log_urls = extract_log_url_from_body(&comment.body.unwrap_or_default());
            }
            else
            {
                process_tags(&issue.body.as_ref().unwrap_or(&"".to_owned()), &config.tags_rules, &mut actions);

                log_urls = get_logs_from_issue_description(&issue).await;

                if log_urls.is_empty() && args.comments
                {
                    print!("No logs found from description. Looking at comments\n");
                    log_urls = get_logs_from_issue_comments(&issue).await;
                }
            }

            log_urls = log_urls.into_iter().unique().collect();

            if !log_urls.is_empty()
            {
                if previous_issue_body.is_some()
                {
                    // This blocks handles the case where an issue is edited to add logs after it was published.
                    // In this case, we should only continue if the previous issue body didn't have log URL's

                    let previous_body_logs_urls = extract_log_url_from_body(&previous_issue_body.as_ref().unwrap());

                    log_urls = log_urls.iter().filter(|e|!previous_body_logs_urls.contains(e)).cloned().collect::<Vec<String>>();
                    if !log_urls.is_empty()
                    {
                        add_message(&("Issue was edited and new log file was found: ".to_owned() + &log_urls[0]), &HashMap::new(), &mut actions.debug_messages);
                    }
                    else
                    {
                        print!("Issue already had log URLs before edit. Skipping");
                        return;
                    }
                }

                if log_urls.len() > 1
                {
                    add_message(&("Multiple log files found, using: ".to_owned() + &log_urls[0]).to_owned(), &HashMap::new(), &mut actions.debug_messages);
                }
    
                let mut logs = download_logs(&log_urls[0]).await;
                Some(process_logs(&mut logs, &config, args.export_xls, &mut actions))
            }
            else
            {
                if args.comment.is_none() && previous_issue_body.is_none()
                {
                    print!("{}\n", "No logs found in issue, adding missing logs message and tags".yellow());

                    for e in config.logs_rules.missing_logs_add_tags
                    {
                        actions.tags.push(e);
                    }

                    add_message(&config.logs_rules.missing_logs_message, &HashMap::new(), &mut actions.user_messages);
                }

                None
            }
        }
    }
    else if args.input_xls.is_some()
    {
        let results: Vec<MatchResult> = read_logs_xls(&args.input_xls.unwrap(), &config.rules);
        Some(LogInformation{appxversion: None, evaluation_result: results, parse_error: false})
    }
    else
    {
        print!("No issue nor logs provided.\n");
        return;
    };

    if results.is_some()
    {
        if args.debug_rules
        {
            print!("{}", "Rules results: \n".bold());

            for e in results.as_ref().unwrap().evaluation_result.as_slice()
            {
                print!("\t{:?} set with captures: {:?}\n", e.name, e.captures)
            }
        }

        apply_actions(results.as_ref().unwrap(), &config.actions, &mut actions);
    }

    // Add the 'similar issues' message if this we're not invoked on a specific comment AND no logs were found

    if actions.show_similar_issues && args.default_message_stdin && previous_issue_body.is_none()
    {
        print!("No conclusion found, reading default message from stdin...\n");

        let default_message = io::read_to_string(io::stdin()).unwrap().trim().to_string();

        if !default_message.is_empty()
        {
            add_message(default_message.as_str(), &HashMap::new(), &mut actions.user_messages);
        }
    }

    print!("{}", "\nLog evaluation results: \n".green().bold());
    if !actions.tags.is_empty()
    {
        print!("Add tags: {:?}\n", actions.tags);
    }

    print!("{}\n", actions.user_messages.green());

    print!("\nDebug messages: \n");
    print!("{}\n", actions.debug_messages);

    if args.issue.is_some() && args.github_token.is_some()
    {
        update_issue(&mut github, *args.issue.as_ref().unwrap(), &actions.user_messages, &actions.debug_messages, &actions.tags).await;
    }
}
