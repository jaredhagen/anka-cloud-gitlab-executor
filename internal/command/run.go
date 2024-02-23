package command

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/veertuinc/anka-cloud-gitlab-executor/internal/ankacloud"
	"github.com/veertuinc/anka-cloud-gitlab-executor/internal/gitlab"
	"github.com/veertuinc/anka-cloud-gitlab-executor/internal/log"
	"golang.org/x/crypto/ssh"
)

const (
	defaultSshUserName = "anka"
	defaultSshPassword = "admin"
)

type runOptions struct {
	sshPassword string
	sshUserName string
}

func NewRunCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:  "run <path_to_script> <stage_name>",
		Args: cobra.ExactArgs(2),
	}

	var runOptions runOptions

	cmd.Flags().StringVar(&runOptions.sshUserName, "ssh-username", "", "The SSH username used to SSH into the VM")
	cmd.Flags().StringVar(&runOptions.sshPassword, "ssh-password", "", "The SSH password used to SSH into the VM")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		env, ok := cmd.Context().Value(contextKey("env")).(gitlab.Environment)
		if !ok {
			return fmt.Errorf("failed to get environment from context")
		}

		runArgs := runArgs{
			scriptPath:  args[0],
			sshPassword: firstNonEmptyString(env.SSHPassword, runOptions.sshPassword, defaultSshPassword),
			sshUserName: firstNonEmptyString(env.SSHUserName, runOptions.sshUserName, defaultSshUserName),
			stageName:   args[1],
		}

		return executeRun(cmd.Context(), env, runArgs)
	}

	return cmd
}

func firstNonEmptyString(strs ...string) string {
	for _, s := range strs {
		if s != "" {
			return s
		}
	}
	return ""
}

type runArgs struct {
	scriptPath  string
	sshPassword string
	sshUserName string
	stageName   string
}

func executeRun(ctx context.Context, env gitlab.Environment, runArgs runArgs) error {
	log.SetOutput(os.Stderr)

	log.Printf("running run stage %s\n", runArgs.stageName)

	apiClientConfig := getAPIClientConfig(env)
	apiClient, err := ankacloud.NewAPIClient(apiClientConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize API client with config +%v: %w", apiClientConfig, err)
	}

	controller := ankacloud.NewController(apiClient)

	instance, err := controller.GetInstanceByExternalId(ctx, env.GitlabJobId)
	if err != nil {
		return fmt.Errorf("failed to get instance by external id %q: %w", env.GitlabJobId, err)
	}

	log.Printf("instance id: %s\n", instance.Id)

	var nodeIp, nodeSshPort string
	if instance.VM == nil {
		return fmt.Errorf("instance has no VM: %+v", instance)
	}

	for _, rule := range instance.VM.PortForwardingRules {
		if rule.VmPort == 22 && rule.Protocol == "tcp" {
			nodeSshPort = fmt.Sprintf("%d", rule.NodePort)
		}
	}
	if nodeSshPort == "" {
		return fmt.Errorf("could not find ssh port forwarded for vm")
	}
	log.Printf("node SSH port to VM: %s\n", nodeSshPort)

	nodeId := instance.NodeId
	node, err := controller.GetNode(ctx, ankacloud.GetNodeRequest{Id: nodeId})
	if err != nil {
		return fmt.Errorf("failed to get node %s: %w", nodeId, err)
	}
	nodeIp = node.IP
	log.Printf("node IP: %s\n", nodeIp)

	gitlabScriptFile, err := os.Open(runArgs.scriptPath)
	if err != nil {
		return fmt.Errorf("failed to open script file at %q: %w", runArgs.scriptPath, err)
	}
	defer gitlabScriptFile.Close()
	log.Printf("gitlab script path: %s", runArgs.scriptPath)

	sshClientConfig := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            runArgs.sshUserName,
		Auth: []ssh.AuthMethod{
			ssh.Password(runArgs.sshPassword),
		},
	}

	addr := fmt.Sprintf("%s:%s", nodeIp, nodeSshPort)
	var sshClient *ssh.Client

	// retry logic mimics what is done by the official Gitlab Runner (true for gitlab runner v16.7.0)
	for i := 0; i < 3; i++ {
		log.Printf("attempt #%d to establish ssh connection to %q\n", i, addr)
		sshClient, err = ssh.Dial("tcp", addr, sshClientConfig)
		if err == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("failed to create new ssh client connection to %q: %w", addr, err)
	}
	defer sshClient.Close()

	log.Println("ssh connection established")

	session, err := sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to start new ssh session: %w", err)
	}
	defer session.Close()
	log.Println("ssh session opened")

	session.Stdin = gitlabScriptFile
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	err = session.Shell()
	if err != nil {
		return fmt.Errorf("failed to start Shell on SSH session: %w", err)
	}

	log.Println("waiting for remote execution to finish")
	err = session.Wait()

	log.Println("remote execution finished")
	return err
}
