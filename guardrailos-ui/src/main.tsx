import React;
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider, useQuery, useMutation } from '@tanstack/react-query';
import axios from 'axios';
import './index.css'; // Tailwind CSS import
import { format } from 'date-fns'; // For date formatting

const queryClient = new QueryClient();

// API Base URL from environment variable, provided by Docker Compose/Vite
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Define TS interfaces for data from backend
interface AuditLogEntry {
  id: string;
  timestamp: string;
  agent_id: string;
  action: string;
  target_resource?: string;
  decision: string;
  policy_id?: string;
  lobster_trap_score?: number;
  hash_chain: string;
  details?: Record<string, any>;
}

interface ApprovalRequestResponse {
  id: string;
  timestamp: string;
  agent_id: string;
  action_type: string;
  payload_hash: string;
  status: 'pending' | 'approved' | 'denied';
  approver_id?: string;
  approval_reason?: string;
  expires_at?: string;
  audit_event_id?: string;
}

interface ApproveRequestPayload {
  approver_id: string;
  approval_reason?: string;
  status: 'approved' | 'denied';
}


const App = () => {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-50">
      <header className="bg-white dark:bg-gray-800 shadow-sm py-4">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <h1 className="text-3xl font-bold leading-tight">GuardrailOS Dashboard</h1>
        </div>
      </header>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <AuditLogList />
          <ApprovalRequestList />
        </div>
      </main>
    </div>
  );
};

const AuditLogList = () => {
  const { data, isLoading, error } = useQuery<AuditLogEntry[], Error>({
    queryKey: ['auditLogs'],
    queryFn: async () => {
      const response = await axios.get(`${API_URL}/audit-logs`);
      return response.data;
    },
    refetchInterval: 5000, // Refetch every 5 seconds
  });

  if (isLoading) return <div className="p-4 bg-white dark:bg-gray-800 shadow rounded-lg">Loading audit logs...</div>;
  if (error) return <div className="p-4 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 shadow rounded-lg">Error: {error.message}</div>;

  const getDecisionColor = (decision: string) => {
    switch (decision) {
      case 'allow': return 'text-green-600 dark:text-green-400';
      case 'deny_policy': return 'text-red-600 dark:text-red-400';
      case 'blocked_lobstertrap': return 'text-purple-600 dark:text-purple-400';
      case 'pending_approval_policy': return 'text-yellow-600 dark:text-yellow-400';
      case 'lobstertrap_operational_error': return 'text-orange-600 dark:text-orange-400';
      default: return 'text-gray-600 dark:text-gray-400';
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 shadow-lg rounded-lg overflow-hidden">
      <div className="px-6 py-4 border-b dark:border-gray-700">
        <h2 className="text-xl font-semibold">Audit Logs</h2>
      </div>
      <div className="p-4 max-h-[calc(100vh-200px)] overflow-y-auto">
        {data?.length === 0 ? (
          <p className="text-gray-500 dark:text-gray-400">No audit logs found.</p>
        ) : (
          <ul className="space-y-4">
            {data?.map((log) => (
              <li key={log.id} className="p-4 border dark:border-gray-700 rounded-md bg-gray-50 dark:bg-gray-800">
                <div className="flex justify-between items-center mb-2">
                  <span className={`font-medium ${getDecisionColor(log.decision)}`}>Decision: {log.decision}</span>
                  <span className="text-sm text-gray-500 dark:text-gray-400">{format(new Date(log.timestamp), 'MMM dd, yyyy HH:mm:ss')}</span>
                </div>
                <p className="text-sm text-gray-700 dark:text-gray-300">
                  <span className="font-semibold">Agent:</span> {log.agent_id} <br />
                  <span className="font-semibold">Action:</span> {log.action} <br />
                  {log.target_resource && <><span className="font-semibold">Resource:</span> {log.target_resource} <br /></>}
                  {log.policy_id && <><span className="font-semibold">Policy ID:</span> {log.policy_id} <br /></>}
                  {log.lobster_trap_score !== undefined && <><span className="font-semibold">LT Score:</span> {log.lobster_trap_score.toFixed(2)} <br /></>}
                </p>
                {/* You can add more details here, perhaps in an expandable section */}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

const ApprovalRequestList = () => {
  const { data, isLoading, error } = useQuery<ApprovalRequestResponse[], Error>({
    queryKey: ['approvalRequests'],
    queryFn: async () => {
      const response = await axios.get(`${API_URL}/approvals`);
      return response.data;
    },
    refetchInterval: 5000, // Refetch every 5 seconds
  });

  const approveMutation = useMutation<ApprovalRequestResponse, Error, { id: string; payload: ApproveRequestPayload }>({
    mutationFn: async ({ id, payload }) => {
      const response = await axios.post(`${API_URL}/approvals/${id}/approve`, payload);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['approvalRequests'] });
      queryClient.invalidateQueries({ queryKey: ['auditLogs'] }); // Approvals also affect audit logs
    },
  });

  const handleApprove = (id: string) => {
    approveMutation.mutate({ id, payload: { approver_id: 'manager-user-123', status: 'approved', approval_reason: 'Reviewed and approved by manager.' } });
  };

  const handleDeny = (id: string) => {
    approveMutation.mutate({ id, payload: { approver_id: 'manager-user-123', status: 'denied', approval_reason: 'Denied by manager, violates company policy.' } });
  };

  if (isLoading) return <div className="p-4 bg-white dark:bg-gray-800 shadow rounded-lg">Loading approval requests...</div>;
  if (error) return <div className="p-4 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 shadow rounded-lg">Error: {error.message}</div>;

  return (
    <div className="bg-white dark:bg-gray-800 shadow-lg rounded-lg overflow-hidden">
      <div className="px-6 py-4 border-b dark:border-gray-700">
        <h2 className="text-xl font-semibold">Approval Requests</h2>
      </div>
      <div className="p-4 max-h-[calc(100vh-200px)] overflow-y-auto">
        {data?.length === 0 ? (
          <p className="text-gray-500 dark:text-gray-400">No approval requests found.</p>
        ) : (
          <ul className="space-y-4">
            {data?.map((request) => (
              <li key={request.id} className="p-4 border dark:border-gray-700 rounded-md bg-gray-50 dark:bg-gray-800">
                <div className="flex justify-between items-center mb-2">
                  <span className={`font-medium ${request.status === 'pending' ? 'text-yellow-600 dark:text-yellow-400' : request.status === 'approved' ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>Status: {request.status.toUpperCase()}</span>
                  <span className="text-sm text-gray-500 dark:text-gray-400">{format(new Date(request.timestamp), 'MMM dd, yyyy HH:mm:ss')}</span>
                </div>
                <p className="text-sm text-gray-700 dark:text-gray-300">
                  <span className="font-semibold">Agent:</span> {request.agent_id} <br />
                  <span className="font-semibold">Action:</span> {request.action_type} <br />
                  <span className="font-semibold">Payload Hash:</span> {request.payload_hash.substring(0, 10)}... <br />
                  {request.expires_at && <><span className="font-semibold">Expires:</span> {format(new Date(request.expires_at), 'MMM dd, yyyy HH:mm')} <br /></>}
                  {request.approver_id && <><span className="font-semibold">Approver:</span> {request.approver_id} <br /></>}
                  {request.approval_reason && <><span className="font-semibold">Reason:</span> {request.approval_reason} <br /></>}
                </p>
                {request.status === 'pending' && (
                  <div className="mt-3 space-x-2">
                    <button
                      onClick={() => handleApprove(request.id)}
                      className="px-4 py-2 bg-green-600 text-white dark:bg-green-700 rounded-md hover:bg-green-700 dark:hover:bg-green-800 transition-colors"
                      disabled={approveMutation.isPending}
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => handleDeny(request.id)}
                      className="px-4 py-2 bg-red-600 text-white dark:bg-red-700 rounded-md hover:bg-red-700 dark:hover:bg-red-800 transition-colors"
                      disabled={approveMutation.isPending}
                    >
                      Deny
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};


ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
);
