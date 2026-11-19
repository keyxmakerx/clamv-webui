package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type agent struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Enabled      bool       `json:"enabled"`
	Online       bool       `json:"online"`
	LastSeenAt   *time.Time `json:"lastSeenAt"`
	Version      *string    `json:"version"`
	ClamdVersion *string    `json:"clamdVersion"`
	Roots        []string   `json:"roots"`
	Slots        int64      `json:"slots"`
	VersionHint  *string    `json:"versionHint"`
}

type schedule struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Cron       string     `json:"cron"`
	Paths      []string   `json:"paths"`
	EndpointID *int64     `json:"endpointId"`
	AgentID    *int64     `json:"agentId"`
	Agent      *string    `json:"agent"`
	Enabled    bool       `json:"enabled"`
	EicarCheck bool       `json:"eicarCheck"`
	LastRunAt  *time.Time `json:"lastRunAt"`
	NextRunAt  *time.Time `json:"nextRunAt"`
}

// Repeatable --path.
type pathList []string

func (p *pathList) String() string     { return strings.Join(*p, ",") }
func (p *pathList) Set(v string) error { *p = append(*p, v); return nil }

func str(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func when(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func (a *App) agents(ctx context.Context, options globals, args []string, client *apiClient) (int, error) {
	if len(args) != 1 || args[0] != "list" {
		return 2, usage("usage: clamctl agents list")
	}
	var values []agent
	if err := client.request(ctx, "GET", "/agents", nil, nil, "", &values, false); err != nil {
		return 1, err
	}
	rows := [][]string{}
	for _, v := range values {
		state := "offline"
		switch {
		case !v.Enabled:
			state = "disabled"
		case v.VersionHint != nil:
			state = "version mismatch"
		case v.Online:
			state = "online"
		}
		rows = append(rows, []string{fmt.Sprint(v.ID), v.Name, state, str(v.Version), strings.Join(v.Roots, ","), when(v.LastSeenAt)})
	}
	return 0, a.output(options, values, []string{"ID", "NAME", "STATE", "VERSION", "ROOTS", "LAST SEEN"}, rows)
}

func (a *App) cancelJob(ctx context.Context, options globals, args []string, client *apiClient) (int, error) {
	if len(args) != 1 {
		return 2, usage("usage: clamctl jobs cancel JOB_ID")
	}
	if err := validJobID(args[0]); err != nil {
		return 2, err
	}
	var value job
	if err := client.request(ctx, "POST", "/jobs/"+args[0]+"/cancel", nil, bytes.NewReader([]byte("{}")), "application/json", &value, false); err != nil {
		return 1, err
	}
	return 0, a.showJob(options, value)
}

func scheduleRows(values []schedule) [][]string {
	rows := [][]string{}
	for _, v := range values {
		where := "server"
		if v.Agent != nil {
			where = "agent:" + *v.Agent
		} else if v.EndpointID != nil {
			where = "endpoint:" + fmt.Sprint(*v.EndpointID)
		}
		rows = append(rows, []string{v.ID, v.Name, v.Cron, where, strconv.FormatBool(v.Enabled), strings.Join(v.Paths, ","), when(v.NextRunAt)})
	}
	return rows
}

var scheduleHeaders = []string{"ID", "NAME", "CRON", "RUNS ON", "ENABLED", "PATHS", "NEXT RUN"}

func (a *App) schedules(ctx context.Context, options globals, args []string, client *apiClient) (int, error) {
	const help = "usage: clamctl schedules list | add NAME --cron EXPR --path P [--path P] [--agent NAME] [--eicar] | run|pause|resume|delete ID"
	if len(args) == 0 {
		return 2, usage(help)
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return 2, usage(help)
		}
		var values []schedule
		if err := client.request(ctx, "GET", "/schedules", nil, nil, "", &values, false); err != nil {
			return 1, err
		}
		return 0, a.output(options, values, scheduleHeaders, scheduleRows(values))
	case "add":
		fs := flag.NewFlagSet("schedules add", flag.ContinueOnError)
		cron := fs.String("cron", "", "Five-field cron expression")
		agentName := fs.String("agent", "", "Run on this agent")
		eicar := fs.Bool("eicar", false, "Run the EICAR control with each run")
		var paths pathList
		fs.Var(&paths, "path", "Folder to scan; repeat for more")
		if err := parseFlags(args[1:], fs); err != nil {
			return 2, err
		}
		if fs.NArg() != 1 || *cron == "" || len(paths) == 0 {
			return 2, usage(help)
		}
		body := map[string]any{"name": fs.Arg(0), "cron": *cron, "paths": []string(paths), "eicarCheck": *eicar}
		if *agentName != "" {
			body["agent"] = *agentName
		} else if options.Endpoint > 0 {
			body["endpointId"] = options.Endpoint
		}
		encoded, _ := json.Marshal(body)
		var value schedule
		if err := client.request(ctx, "POST", "/schedules", nil, bytes.NewReader(encoded), "application/json", &value, false); err != nil {
			return 1, err
		}
		return 0, a.output(options, value, scheduleHeaders, scheduleRows([]schedule{value}))
	case "run", "pause", "resume", "delete":
		if len(args) != 2 || !jobIDPattern.MatchString(args[1]) {
			return 2, usage(help)
		}
		id := args[1]
		switch args[0] {
		case "run":
			var result struct {
				Created int `json:"created"`
			}
			if err := client.request(ctx, "POST", "/schedules/"+id+"/run", nil, bytes.NewReader([]byte("{}")), "application/json", &result, false); err != nil {
				return 1, err
			}
			return 0, a.output(options, result, []string{"SCHEDULE", "JOBS QUEUED"}, [][]string{{id, fmt.Sprint(result.Created)}})
		case "delete":
			if err := client.request(ctx, "DELETE", "/schedules/"+id, nil, nil, "", nil, false); err != nil {
				return 1, err
			}
			return 0, a.output(options, map[string]any{"deleted": id}, []string{"DELETED"}, [][]string{{id}})
		default:
			encoded, _ := json.Marshal(map[string]bool{"enabled": args[0] == "resume"})
			var value schedule
			if err := client.request(ctx, "PATCH", "/schedules/"+id, nil, bytes.NewReader(encoded), "application/json", &value, false); err != nil {
				return 1, err
			}
			return 0, a.output(options, value, scheduleHeaders, scheduleRows([]schedule{value}))
		}
	default:
		return 2, usage(help)
	}
}
