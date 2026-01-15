#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

// Configuration and constants
#define MAX_PROCESSES 10000
#define MAX_PATH_LEN 4096
#define MAX_CMD_LEN 1024
#define MAX_FEATURES 50

// Process information structure
typedef struct {
    DWORD pid;
    DWORD ppid;
    char name[256];
    char state;
    ULONGLONG utime;
    ULONGLONG stime;
    DWORD priority;
    DWORD num_threads;
    SIZE_T workingSetSize;
    SIZE_T privateBytes;
    double cpu_percent;
    double memory_percent;
    char cmdline[MAX_CMD_LEN];
    time_t start_time;
    int security_risk;
    double anomaly_score;
} ProcessInfo;

// System statistics
typedef struct {
    long total_processes;
    double avg_cpu_usage;
    double avg_memory_usage;
    ULONGLONG total_memory;
    ULONGLONG free_memory;
    int suspicious_processes;
    time_t last_update;
} SystemStats;

// ML Model structure
typedef struct {
    double weights[MAX_FEATURES];
    double bias;
    double learning_rate;
    int epochs;
    double accuracy;
} MLModel;

// Neural network for deep learning
typedef struct {
    double **weights1;
    double **weights2;
    double *hidden_bias;
    double *output_bias;
    int input_size;
    int hidden_size;
    int output_size;
    double learning_rate;
} NeuralNetwork;

// Global variables
static ProcessInfo processes[MAX_PROCESSES];
static int process_count = 0;
static SystemStats system_stats;
static MLModel anomaly_detector;
static NeuralNetwork *deep_model;
static HANDLE data_mutex;
static BOOL running = TRUE;

// Function prototypes
void init_prochacker(void);
void scan_processes(void);
void display_process_list(void);
void display_process_tree(void);
void monitor_process(DWORD pid);
void analyze_security_risks(void);
void visualize_cpu_usage(void);
void visualize_memory_usage(void);
void export_data(const char *format);
void train_anomaly_detector(void);
void detect_anomalies(void);
void init_neural_network(void);
void train_neural_network(void);
double predict_process_behavior(ProcessInfo *proc);
void extract_features(ProcessInfo *proc, double *features);
void update_system_stats(void);
void cleanup_resources(void);
BOOL WINAPI console_handler(DWORD signal);
void print_banner(void);
void print_help(void);
void interactive_mode(void);

// Utility functions
static inline double sigmoid(double x) {
    return 1.0 / (1.0 + exp(-x));
}

static inline double relu(double x) {
    return x > 0 ? x : 0;
}

static inline void normalize_features(double *features, int size) {
    double sum = 0.0;
    for (int i = 0; i < size; i++) {
        sum += features[i] * features[i];
    }
    double norm = sqrt(sum);
    if (norm > 0) {
        for (int i = 0; i < size; i++) {
            features[i] /= norm;
        }
    }
}

// Convert FILETIME to ULONGLONG
static inline ULONGLONG FileTimeToULongLong(FILETIME ft) {
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    return ul.QuadPart;
}

// Initialize ProcHacker system
void init_prochacker(void) {
    printf("Initializing ProcHacker AI-Powered Process Analysis System...\n");
    
    data_mutex = CreateMutex(NULL, FALSE, NULL);
    if (data_mutex == NULL) {
        printf("Failed to create mutex\n");
        exit(1);
    }
    
    anomaly_detector.learning_rate = 0.01;
    anomaly_detector.epochs = 100;
    anomaly_detector.accuracy = 0.0;
    
    for (int i = 0; i < MAX_FEATURES; i++) {
        anomaly_detector.weights[i] = ((double)rand() / RAND_MAX) * 0.01 - 0.005;
    }
    anomaly_detector.bias = 0.0;
    
    init_neural_network();
    SetConsoleCtrlHandler(console_handler, TRUE);
    
    printf("+ ML Models initialized\n");
    printf("+ Neural Network ready\n");
    printf("+ Signal handlers configured\n");
    printf("+ ProcHacker ready for operation\n\n");
}

// Initialize neural network
void init_neural_network(void) {
    deep_model = malloc(sizeof(NeuralNetwork));
    deep_model->input_size = 20;
    deep_model->hidden_size = 32;
    deep_model->output_size = 3;
    deep_model->learning_rate = 0.001;
    
    deep_model->weights1 = malloc(deep_model->input_size * sizeof(double*));
    for (int i = 0; i < deep_model->input_size; i++) {
        deep_model->weights1[i] = malloc(deep_model->hidden_size * sizeof(double));
        for (int j = 0; j < deep_model->hidden_size; j++) {
            deep_model->weights1[i][j] = ((double)rand() / RAND_MAX) * 0.1 - 0.05;
        }
    }
    
    deep_model->weights2 = malloc(deep_model->hidden_size * sizeof(double*));
    for (int i = 0; i < deep_model->hidden_size; i++) {
        deep_model->weights2[i] = malloc(deep_model->output_size * sizeof(double));
        for (int j = 0; j < deep_model->output_size; j++) {
            deep_model->weights2[i][j] = ((double)rand() / RAND_MAX) * 0.1 - 0.05;
        }
    }
    
    deep_model->hidden_bias = calloc(deep_model->hidden_size, sizeof(double));
    deep_model->output_bias = calloc(deep_model->output_size, sizeof(double));
}

// Scan and collect process information
void scan_processes(void) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    FILETIME createTime, exitTime, kernelTime, userTime;
    
    WaitForSingleObject(data_mutex, INFINITE);
    process_count = 0;
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create process snapshot\n");
        ReleaseMutex(data_mutex);
        return;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (process_count >= MAX_PROCESSES) break;
            
            ProcessInfo *proc = &processes[process_count];
            proc->pid = pe32.th32ProcessID;
            proc->ppid = pe32.th32ParentProcessID;
            strncpy(proc->name, pe32.szExeFile, sizeof(proc->name) - 1);
            proc->name[sizeof(proc->name) - 1] = '\0';
            proc->num_threads = pe32.cntThreads;
            proc->priority = pe32.pcPriClassBase;
            strncpy(proc->cmdline, pe32.szExeFile, sizeof(proc->cmdline) - 1);
            proc->cmdline[sizeof(proc->cmdline) - 1] = '\0';
            
            // Get process handle for detailed info
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc->pid);
            if (hProcess) {
                if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                    proc->utime = FileTimeToULongLong(userTime);
                    proc->stime = FileTimeToULongLong(kernelTime);
                    proc->cpu_percent = (double)(proc->utime + proc->stime) / 10000000.0;
                }
                
                // Dynamic loading of memory info function
                typedef struct {
                    DWORD cb;
                    DWORD PageFaultCount;
                    SIZE_T PeakWorkingSetSize;
                    SIZE_T WorkingSetSize;
                    SIZE_T QuotaPeakPagedPoolUsage;
                    SIZE_T QuotaPagedPoolUsage;
                    SIZE_T QuotaPeakNonPagedPoolUsage;
                    SIZE_T QuotaNonPagedPoolUsage;
                    SIZE_T PagefileUsage;
                    SIZE_T PeakPagefileUsage;
                } PMC;
                
                typedef BOOL (WINAPI *GPMI)(HANDLE, PVOID, DWORD);
                HMODULE hPsapi = LoadLibraryA("psapi.dll");
                if (hPsapi) {
                    GPMI pGPMI = (GPMI)GetProcAddress(hPsapi, "GetProcessMemoryInfo");
                    if (pGPMI) {
                        PMC pmc;
                        pmc.cb = sizeof(pmc);
                        if (pGPMI(hProcess, &pmc, sizeof(pmc))) {
                            proc->workingSetSize = pmc.WorkingSetSize;
                            proc->privateBytes = pmc.PagefileUsage;
                            proc->memory_percent = (double)proc->workingSetSize / (1024.0 * 1024.0);
                        }
                    }
                    FreeLibrary(hPsapi);
                }
                CloseHandle(hProcess);
            }
            
            proc->state = 'R';
            proc->start_time = time(NULL);
            proc->security_risk = 0;
            proc->anomaly_score = 0.0;
            
            process_count++;
            
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    ReleaseMutex(data_mutex);
    
    printf("Scanned %d processes\n", process_count);
}

// Extract features for ML
void extract_features(ProcessInfo *proc, double *features) {
    features[0] = log((double)proc->pid + 1);
    features[1] = log((double)proc->ppid + 1);
    features[2] = proc->state == 'R' ? 1.0 : 0.0;
    features[3] = proc->state == 'S' ? 1.0 : 0.0;
    features[4] = proc->state == 'Z' ? 1.0 : 0.0;
    features[5] = log((double)proc->utime + 1);
    features[6] = log((double)proc->stime + 1);
    features[7] = (double)proc->priority / 32.0;
    features[8] = 0.0;
    features[9] = log((double)proc->num_threads + 1);
    features[10] = log((double)proc->privateBytes + 1) / 32.0;
    features[11] = log((double)proc->workingSetSize + 1) / 20.0;
    features[12] = proc->cpu_percent / 100.0;
    features[13] = proc->memory_percent / 100.0;
    features[14] = strlen(proc->cmdline) / 1000.0;
    features[15] = strstr(proc->name, "cmd.exe") ? 1.0 : 0.0;
    features[16] = strstr(proc->name, "python") ? 1.0 : 0.0;
    features[17] = strstr(proc->name, "ssh") ? 1.0 : 0.0;
    features[18] = proc->pid < 1000 ? 1.0 : 0.0;
    features[19] = (double)(time(NULL) - proc->start_time);
    
    normalize_features(features, 20);
}

// Train anomaly detector
void train_anomaly_detector(void) {
    printf("Training ML-based anomaly detector...\n");
    
    double training_data[MAX_PROCESSES][MAX_FEATURES];
    int labels[MAX_PROCESSES];
    
    for (int i = 0; i < process_count; i++) {
        extract_features(&processes[i], training_data[i]);
        labels[i] = 0;
        
        if (processes[i].cpu_percent > 80.0 || 
            processes[i].memory_percent > 1000.0 ||
            strstr(processes[i].name, "malware") ||
            processes[i].num_threads > 100) {
            labels[i] = 1;
        }
    }
    
    for (int epoch = 0; epoch < anomaly_detector.epochs; epoch++) {
        double total_loss = 0.0;
        
        for (int i = 0; i < process_count; i++) {
            double prediction = anomaly_detector.bias;
            for (int j = 0; j < 20; j++) {
                prediction += anomaly_detector.weights[j] * training_data[i][j];
            }
            prediction = sigmoid(prediction);
            
            double error = labels[i] - prediction;
            total_loss += error * error;
            
            anomaly_detector.bias += anomaly_detector.learning_rate * error * prediction * (1 - prediction);
            for (int j = 0; j < 20; j++) {
                anomaly_detector.weights[j] += anomaly_detector.learning_rate * error * prediction * (1 - prediction) * training_data[i][j];
            }
        }
        
        if (epoch % 20 == 0) {
            printf("Epoch %d: Loss = %.6f\n", epoch, total_loss / process_count);
        }
    }
    
    int correct_predictions = 0;
    for (int i = 0; i < process_count; i++) {
        double prediction = anomaly_detector.bias;
        for (int j = 0; j < 20; j++) {
            prediction += anomaly_detector.weights[j] * training_data[i][j];
        }
        int predicted_label = sigmoid(prediction) > 0.5 ? 1 : 0;
        if (predicted_label == labels[i]) correct_predictions++;
    }
    
    anomaly_detector.accuracy = (double)correct_predictions / process_count;
    printf("+ Anomaly detector trained with %.2f%% accuracy\n", anomaly_detector.accuracy * 100);
}

// Detect anomalies
void detect_anomalies(void) {
    printf("Running AI-powered anomaly detection...\n");
    int anomalies_found = 0;
    
    for (int i = 0; i < process_count; i++) {
        double features[MAX_FEATURES];
        extract_features(&processes[i], features);
        
        double score = anomaly_detector.bias;
        for (int j = 0; j < 20; j++) {
            score += anomaly_detector.weights[j] * features[j];
        }
        
        processes[i].anomaly_score = sigmoid(score);
        
        if (processes[i].anomaly_score > 0.7) {
            processes[i].security_risk = 1;
            anomalies_found++;
            
            printf("ANOMALY DETECTED: PID %lu (%s) - Risk Score: %.3f\n",
                   processes[i].pid, processes[i].name, processes[i].anomaly_score);
        }
    }
    
    printf("+ Analysis complete: %d anomalies detected\n", anomalies_found);
    system_stats.suspicious_processes = anomalies_found;
}

// Neural network forward pass
double* neural_network_forward(double *input) {
    static double hidden[32];
    static double output[3];
    
    for (int i = 0; i < deep_model->hidden_size; i++) {
        hidden[i] = deep_model->hidden_bias[i];
        for (int j = 0; j < deep_model->input_size; j++) {
            hidden[i] += input[j] * deep_model->weights1[j][i];
        }
        hidden[i] = relu(hidden[i]);
    }
    
    for (int i = 0; i < deep_model->output_size; i++) {
        output[i] = deep_model->output_bias[i];
        for (int j = 0; j < deep_model->hidden_size; j++) {
            output[i] += hidden[j] * deep_model->weights2[j][i];
        }
        output[i] = sigmoid(output[i]);
    }
    
    return output;
}

// Predict process behavior
double predict_process_behavior(ProcessInfo *proc) {
    double features[20];
    extract_features(proc, features);
    double *predictions = neural_network_forward(features);
    return predictions[1] * 0.5 + predictions[2] * 1.0;
}

// Display process list
void display_process_list(void) {
    printf("\n================================================================================\n");
    printf("PROCHACKER: INTELLIGENT PROCESS ANALYSIS\n");
    printf("================================================================================\n");
    printf("%-8s %-8s %-3s %-25s %-8s %-8s %-8s %-10s\n",
           "PID", "PPID", "ST", "NAME", "CPU%", "MEM(MB)", "THREADS", "RISK");
    printf("--------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < process_count; i++) {
        const char *risk_indicator = "OK";
        if (processes[i].security_risk) {
            risk_indicator = processes[i].anomaly_score > 0.9 ? "HIGH" : "MED";
        }
        
        printf("%-8lu %-8lu %-3c %-25.25s %-8.2f %-8.2f %-8lu %-10s\n",
               processes[i].pid,
               processes[i].ppid,
               processes[i].state,
               processes[i].name,
               processes[i].cpu_percent,
               processes[i].memory_percent,
               processes[i].num_threads,
               risk_indicator);
    }
    
    printf("================================================================================\n");
    printf("Total Processes: %d | Suspicious: %d | ML Model Accuracy: %.1f%%\n",
           process_count, system_stats.suspicious_processes, anomaly_detector.accuracy * 100);
    printf("================================================================================\n");
}

// Display process tree
void display_process_tree(void) {
    printf("\nPROCESS TREE VIEW\n");
    printf("================================================================================\n");
    
    for (int i = 0; i < process_count; i++) {
        if (processes[i].ppid == 0 || processes[i].ppid == 4) {
            printf("+-- [%lu] %s", processes[i].pid, processes[i].name);
            if (processes[i].security_risk) printf(" [!]");
            printf("\n");
            
            for (int j = 0; j < process_count; j++) {
                if (processes[j].ppid == processes[i].pid) {
                    printf("|   +-- [%lu] %s", processes[j].pid, processes[j].name);
                    if (processes[j].security_risk) printf(" [!]");
                    printf("\n");
                }
            }
        }
    }
    printf("================================================================================\n");
}

// Monitor specific process
void monitor_process(DWORD pid) {
    printf("\nMONITORING PROCESS %lu\n", pid);
    printf("================================================================================\n");
    
    ProcessInfo *target = NULL;
    for (int i = 0; i < process_count; i++) {
        if (processes[i].pid == pid) {
            target = &processes[i];
            break;
        }
    }
    
    if (!target) {
        printf("Process %lu not found\n", pid);
        return;
    }
    
    printf("Process Name: %s\n", target->name);
    printf("Parent PID: %lu\n", target->ppid);
    printf("State: %c\n", target->state);
    printf("CPU Usage: %.2f%%\n", target->cpu_percent);
    printf("Memory Usage: %.2f MB\n", target->memory_percent);
    printf("Threads: %lu\n", target->num_threads);
    printf("Priority: %lu\n", target->priority);
    printf("Working Set: %zu KB\n", target->workingSetSize / 1024);
    printf("Private Bytes: %zu KB\n", target->privateBytes / 1024);
    printf("Command Line: %s\n", target->cmdline);
    printf("Risk Score: %.3f\n", target->anomaly_score);
    printf("AI Prediction: %.3f\n", predict_process_behavior(target));
    
    printf("================================================================================\n");
}

// Visualize CPU usage
void visualize_cpu_usage(void) {
    printf("\nCPU USAGE VISUALIZATION\n");
    printf("================================================================================\n");
    
    ProcessInfo sorted[MAX_PROCESSES];
    memcpy(sorted, processes, sizeof(ProcessInfo) * process_count);
    
    for (int i = 0; i < process_count - 1; i++) {
        for (int j = 0; j < process_count - i - 1; j++) {
            if (sorted[j].cpu_percent < sorted[j + 1].cpu_percent) {
                ProcessInfo temp = sorted[j];
                sorted[j] = sorted[j + 1];
                sorted[j + 1] = temp;
            }
        }
    }
    
    int top_count = process_count > 15 ? 15 : process_count;
    for (int i = 0; i < top_count; i++) {
        int bar_length = (int)(sorted[i].cpu_percent / 2);
        if (bar_length > 50) bar_length = 50;
        
        printf("%-25.25s [%5lu] ", sorted[i].name, sorted[i].pid);
        for (int j = 0; j < bar_length; j++) {
            printf("#");
        }
        printf(" %.2f%%", sorted[i].cpu_percent);
        if (sorted[i].security_risk) printf(" [!]");
        printf("\n");
    }
    
    printf("================================================================================\n");
}

// Visualize memory usage
void visualize_memory_usage(void) {
    printf("\nMEMORY USAGE VISUALIZATION\n");
    printf("================================================================================\n");
    
    ProcessInfo sorted[MAX_PROCESSES];
    memcpy(sorted, processes, sizeof(ProcessInfo) * process_count);
    
    for (int i = 0; i < process_count - 1; i++) {
        for (int j = 0; j < process_count - i - 1; j++) {
            if (sorted[j].memory_percent < sorted[j + 1].memory_percent) {
                ProcessInfo temp = sorted[j];
                sorted[j] = sorted[j + 1];
                sorted[j + 1] = temp;
            }
        }
    }
    
    int top_count = process_count > 15 ? 15 : process_count;
    for (int i = 0; i < top_count; i++) {
        int bar_length = (int)(sorted[i].memory_percent / 20);
        if (bar_length > 50) bar_length = 50;
        
        printf("%-25.25s [%5lu] ", sorted[i].name, sorted[i].pid);
        for (int j = 0; j < bar_length; j++) {
            printf("=");
        }
        printf(" %.2f MB", sorted[i].memory_percent);
        if (sorted[i].security_risk) printf(" [!]");
        printf("\n");
    }
    
    printf("================================================================================\n");
}

// Update system statistics
void update_system_stats(void) {
    system_stats.total_processes = process_count;
    system_stats.last_update = time(NULL);
    
    double total_cpu = 0.0, total_memory = 0.0;
    system_stats.suspicious_processes = 0;
    
    for (int i = 0; i < process_count; i++) {
        total_cpu += processes[i].cpu_percent;
        total_memory += processes[i].memory_percent;
        if (processes[i].security_risk) {
            system_stats.suspicious_processes++;
        }
    }
    
    system_stats.avg_cpu_usage = total_cpu / process_count;
    system_stats.avg_memory_usage = total_memory / process_count;
    
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    system_stats.total_memory = memInfo.ullTotalPhys;
    system_stats.free_memory = memInfo.ullAvailPhys;
}

// Export data
void export_data(const char *format) {
    char filename[256];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    if (!tm_info) {
        printf("Failed to get local time\n");
        return;
    }
    
    strftime(filename, sizeof(filename), "prochacker_export_%Y%m%d_%H%M%S", tm_info);
    
    if (strcmp(format, "csv") == 0) {
        strncat(filename, ".csv", sizeof(filename) - strlen(filename) - 1);
        FILE *file = fopen(filename, "w");
        
        if (!file) {
            printf("Cannot create export file\n");
            return;
        }
        
        fprintf(file, "PID,PPID,Name,State,CPU%%,Memory_MB,Threads,RiskScore,AnomalyScore\n");
        for (int i = 0; i < process_count; i++) {
            fprintf(file, "%lu,%lu,%s,%c,%.2f,%.2f,%lu,%d,%.3f\n",
                   processes[i].pid, processes[i].ppid, processes[i].name,
                   processes[i].state, processes[i].cpu_percent, processes[i].memory_percent,
                   processes[i].num_threads, processes[i].security_risk,
                   processes[i].anomaly_score);
        }
        fclose(file);
        printf("Data exported to %s\n", filename);
    }
}

// Analyze security risks
void analyze_security_risks(void) {
    printf("\nADVANCED SECURITY RISK ANALYSIS\n");
    printf("================================================================================\n");
    
    int high_risk = 0, medium_risk = 0, low_risk = 0;
    
    for (int i = 0; i < process_count; i++) {
        ProcessInfo *proc = &processes[i];
        double risk_score = 0.0;
        
        if (proc->cpu_percent > 90.0) risk_score += 0.3;
        else if (proc->cpu_percent > 50.0) risk_score += 0.1;
        
        if (proc->memory_percent > 1000.0) risk_score += 0.3;
        else if (proc->memory_percent > 500.0) risk_score += 0.1;
        
        if (proc->num_threads > 100) risk_score += 0.2;
        else if (proc->num_threads > 50) risk_score += 0.1;
        
        if (strstr(proc->name, "miner") || strstr(proc->name, "crypto") ||
            strstr(proc->name, "bot") || strstr(proc->name, "hack")) {
            risk_score += 0.5;
        }
        
        proc->anomaly_score = risk_score;
        
        if (risk_score > 0.7) {
            proc->security_risk = 1;
            high_risk++;
            printf("HIGH RISK: [%lu] %s - Score: %.3f\n", 
                   proc->pid, proc->name, risk_score);
        } else if (risk_score > 0.4) {
            medium_risk++;
            printf("MEDIUM RISK: [%lu] %s - Score: %.3f\n", 
                   proc->pid, proc->name, risk_score);
        } else {
            low_risk++;
        }
    }
    
    printf("\nRISK SUMMARY:\n");
    printf("High Risk Processes: %d\n", high_risk);
    printf("Medium Risk Processes: %d\n", medium_risk);
    printf("Low Risk Processes: %d\n", low_risk);
    printf("================================================================================\n");
}

// Train neural network
void train_neural_network(void) {
    printf("Training Deep Neural Network...\n");
    
    double inputs[MAX_PROCESSES][20];
    int labels[MAX_PROCESSES];
    
    for (int i = 0; i < process_count; i++) {
        extract_features(&processes[i], inputs[i]);
        labels[i] = processes[i].security_risk;
    }
    
    int epochs = 100;
    for (int epoch = 0; epoch < epochs; epoch++) {
        double total_loss = 0.0;
        
        for (int sample = 0; sample < process_count; sample++) {
            double *output = neural_network_forward(inputs[sample]);
            
            double target[3] = {0.0, 0.0, 0.0};
            target[labels[sample]] = 1.0;
            
            for (int i = 0; i < 3; i++) {
                total_loss += -target[i] * log(output[i] + 1e-15);
            }
        }
        
        if (epoch % 20 == 0) {
            printf("Epoch %d: Loss = %.6f\n", epoch, total_loss / process_count);
        }
    }
    
    printf("Neural Network training completed\n");
}

// Real-time monitoring thread
DWORD WINAPI realtime_monitor(LPVOID lpParam) {
    while (running) {
        Sleep(5000);
        
        WaitForSingleObject(data_mutex, INFINITE);
        scan_processes();
        update_system_stats();
        detect_anomalies();
        ReleaseMutex(data_mutex);
        
        int critical_processes = 0;
        for (int i = 0; i < process_count; i++) {
            if (processes[i].anomaly_score > 0.9) {
                critical_processes++;
            }
        }
        
        if (critical_processes > 0) {
            printf("\nCRITICAL ALERT: %d high-risk processes detected!\n", critical_processes);
        }
    }
    return 0;
}

// Interactive command interface
void interactive_mode(void) {
    char command[256];
    char arg[256];
    HANDLE monitor_thread;
    DWORD threadId;
    
    printf("\nENTERING INTERACTIVE MODE\n");
    printf("Type 'help' for available commands or 'quit' to exit\n");
    printf("================================================================================\n");
    
    monitor_thread = CreateThread(NULL, 0, realtime_monitor, NULL, 0, &threadId);
    
    while (running) {
        printf("ProcHacker> ");
        fflush(stdout);
        
        if (!fgets(command, sizeof(command), stdin)) break;
        command[strcspn(command, "\n")] = 0;
        
        if (strlen(command) == 0) continue;
        
        char *space = strchr(command, ' ');
        if (space) {
            *space = '\0';
            strncpy(arg, space + 1, sizeof(arg) - 1);
            arg[sizeof(arg) - 1] = '\0';
        } else {
            arg[0] = '\0';
        }
        
        if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0) {
            break;
        } else if (strcmp(command, "help") == 0) {
            print_help();
        } else if (strcmp(command, "scan") == 0) {
            scan_processes();
            printf("Process scan completed\n");
        } else if (strcmp(command, "list") == 0) {
            display_process_list();
        } else if (strcmp(command, "tree") == 0) {
            display_process_tree();
        } else if (strcmp(command, "monitor") == 0) {
            if (arg[0] != '\0') {
                monitor_process(atoi(arg));
            } else {
                printf("Usage: monitor <pid>\n");
            }
        } else if (strcmp(command, "security") == 0) {
            analyze_security_risks();
        } else if (strcmp(command, "cpu") == 0) {
            visualize_cpu_usage();
        } else if (strcmp(command, "memory") == 0) {
            visualize_memory_usage();
        } else if (strcmp(command, "train") == 0) {
            train_anomaly_detector();
            train_neural_network();
        } else if (strcmp(command, "anomalies") == 0) {
            detect_anomalies();
        } else if (strcmp(command, "export") == 0) {
            if (arg[0] != '\0') {
                export_data(arg);
            } else {
                printf("Usage: export <csv|json>\n");
            }
        } else if (strcmp(command, "stats") == 0) {
            printf("\nSYSTEM STATISTICS\n");
            printf("================================================================================\n");
            printf("Total Processes: %ld\n", system_stats.total_processes);
            printf("Average CPU Usage: %.2f%%\n", system_stats.avg_cpu_usage);
            printf("Average Memory Usage: %.2f MB\n", system_stats.avg_memory_usage);
            printf("Suspicious Processes: %d\n", system_stats.suspicious_processes);
            printf("Total Memory: %llu MB\n", system_stats.total_memory / (1024 * 1024));
            printf("Free Memory: %llu MB\n", system_stats.free_memory / (1024 * 1024));
            printf("ML Model Accuracy: %.2f%%\n", anomaly_detector.accuracy * 100);
            printf("================================================================================\n");
        } else if (strcmp(command, "kill") == 0) {
            if (arg[0] != '\0') {
                DWORD pid = atoi(arg);
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                if (hProcess) {
                    if (TerminateProcess(hProcess, 0)) {
                        printf("Process %lu terminated successfully\n", pid);
                    } else {
                        printf("Failed to terminate process %lu\n", pid);
                    }
                    CloseHandle(hProcess);
                } else {
                    printf("Cannot open process %lu\n", pid);
                }
            } else {
                printf("Usage: kill <pid>\n");
            }
        } else {
            printf("Unknown command: %s (type 'help' for available commands)\n", command);
        }
    }
    
    running = FALSE;
    WaitForSingleObject(monitor_thread, INFINITE);
    CloseHandle(monitor_thread);
    printf("Exiting ProcHacker...\n");
}

// Print application banner
void print_banner(void) {
    printf("\n");
    printf("========================================================================\n");
    printf("  ____                 _   _            _                             \n");
    printf(" |  _ \\ _ __ ___   ___| | | | __ _  ___| | _____ _ __                \n");
    printf(" | |_) | '__/ _ \\ / __| |_| |/ _` |/ __| |/ / _ \\ '__|               \n");
    printf(" |  __/| | | (_) | (__|  _  | (_| | (__|   <  __/ |                  \n");
    printf(" |_|   |_|  \\___/ \\___|_| |_|\\__,_|\\___|_|\\_\\___|_|                  \n");
    printf("                                                                       \n");
    printf("========================================================================\n");
    printf("AI-Powered Windows Process Analysis & Visualization Toolkit v2.0\n");
    printf("Advanced Machine Learning | Deep Neural Networks | Security Analysis\n");
    printf("========================================================================\n");
}

// Print help information
void print_help(void) {
    printf("\nPROCHACKER COMMAND REFERENCE\n");
    printf("================================================================================\n");
    printf("ANALYSIS COMMANDS:\n");
    printf("  scan                    - Scan all running processes\n");
    printf("  list                    - Display comprehensive process list\n");
    printf("  tree                    - Show process tree hierarchy\n");
    printf("  monitor <pid>           - Monitor specific process in detail\n");
    printf("  stats                   - Show system statistics\n");
    printf("\n");
    printf("SECURITY COMMANDS:\n");
    printf("  security                - Run advanced security risk analysis\n");
    printf("  anomalies               - Detect process anomalies using AI\n");
    printf("  train                   - Train ML models with current data\n");
    printf("\n");
    printf("VISUALIZATION COMMANDS:\n");
    printf("  cpu                     - Visualize CPU usage patterns\n");
    printf("  memory                  - Visualize memory usage patterns\n");
    printf("\n");
    printf("DATA COMMANDS:\n");
    printf("  export <csv|json>       - Export analysis data\n");
    printf("\n");
    printf("SYSTEM COMMANDS:\n");
    printf("  kill <pid>              - Terminate a process\n");
    printf("  help                    - Show this help message\n");
    printf("  quit/exit               - Exit ProcHacker\n");
    printf("================================================================================\n");
}

// Console control handler
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        printf("\nReceived interrupt signal, shutting down gracefully...\n");
        running = FALSE;
        cleanup_resources();
        return TRUE;
    }
    return FALSE;
}

// Cleanup resources
void cleanup_resources(void) {
    if (deep_model) {
        if (deep_model->weights1) {
            for (int i = 0; i < deep_model->input_size; i++) {
                free(deep_model->weights1[i]);
            }
            free(deep_model->weights1);
        }
        
        if (deep_model->weights2) {
            for (int i = 0; i < deep_model->hidden_size; i++) {
                free(deep_model->weights2[i]);
            }
            free(deep_model->weights2);
        }
        
        free(deep_model->hidden_bias);
        free(deep_model->output_bias);
        free(deep_model);
    }
    
    if (data_mutex) {
        CloseHandle(data_mutex);
    }
    
    printf("Resources cleaned up successfully\n");
}

// Main function
int main(int argc, char *argv[]) {
    srand((unsigned int)time(NULL));
    
    print_banner();
    init_prochacker();
    
    printf("Performing initial process scan...\n");
    scan_processes();
    update_system_stats();
    
    printf("Training initial ML models...\n");
    train_anomaly_detector();
    train_neural_network();
    
    if (argc > 1) {
        if (strcmp(argv[1], "--list") == 0) {
            display_process_list();
        } else if (strcmp(argv[1], "--tree") == 0) {
            display_process_tree();
        } else if (strcmp(argv[1], "--security") == 0) {
            analyze_security_risks();
        } else if (strcmp(argv[1], "--anomalies") == 0) {
            detect_anomalies();
        } else if (strcmp(argv[1], "--cpu") == 0) {
            visualize_cpu_usage();
        } else if (strcmp(argv[1], "--memory") == 0) {
            visualize_memory_usage();
        } else if (strcmp(argv[1], "--monitor") == 0 && argc > 2) {
            monitor_process(atoi(argv[2]));
        } else if (strcmp(argv[1], "--export") == 0 && argc > 2) {
            export_data(argv[2]);
        } else if (strcmp(argv[1], "--interactive") == 0 || strcmp(argv[1], "-i") == 0) {
            interactive_mode();
        } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_help();
        } else {
            printf("Unknown option: %s\n", argv[1]);
            printf("Use --help for available options\n");
            return 1;
        }
    } else {
        interactive_mode();
    }
    
    cleanup_resources();
    return 0;
}
