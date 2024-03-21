# WTI

WTI is a tool to automatically triage WSL issues based on description and log file content. 

## Building


Build via: 

```
$ git clone https://github.com/OneBlue/wti
$ cd wti
$ cargo build
```

## Usage

See `wti --help` for full command line information. Basic usage: 

```
$ wti --issue <issue-number> [--ignore-tags] [--config config-path] [--github-token token] [--debug-rules]
```