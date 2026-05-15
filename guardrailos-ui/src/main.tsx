import React;
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider, useQuery, useMutation } from '@tanstack/react-query';
import axios from 'axios';
import './index.css'; // Tailwind CSS import
import { format } from 'date-fns'; // For date formatting

// shadcn/ui components (these imports assume you've run `npx shadcn-ui add button` etc.)
import { Button } from './components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Badge } from './components/ui/badge';
import { ScrollArea } from './components/ui/scroll-area';

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

  if (isLoading) return <Card className="p-4"><CardContent>Loading audit logs...</CardContent></Card>;
  if (error) return <Card className="p-4 bg-red-100 border-red-400 text-red-700"><CardContent>Error: {error.message}</CardContent></Card>;

  const getDecisionVariant = (decision: string) => {
    switch (decision) {
      case 'allow': return 'success';
      case 'deny_policy': return 'destructive';
      case 'blocked_lobstertrap': return 'info'; // Custom variant or use secondary
      case 'pending_approval_policy': return 'warning'; // Custom variant or use secondary
      case 'lobstertrap_operational_error': return 'destructive';
      default: return 'secondary';
    }
  };

  return (
    <Card className="shadow-lg rounded-lg overflow-hidden">
      <CardHeader>
        <CardTitle>Audit Logs</CardTitle>
        <CardDescription>Recent actions by AI agents and policy decisions.</CardDescription>
      </CardHeader>
      <CardContent className="p-4">
        <ScrollArea className="h-[calc(100vh-320px)] pr-4"> {/* Adjust height dynamically */}
          {data?.length === 0 ? (
            <p className="text-muted-foreground">No audit logs found.</p>
          ) : (
            <ul className="space-y-4">
              {data?.map((log) => (
                <Card key={log.id} className="p-4">
                  <div className="flex justify-between items-start mb-2">
                    <Badge variant={getDecisionVariant(log.decision)} className="capitalize">{log.decision.replace(/_/g, ' ')}</Badge>
                    <span className="text-sm text-muted-foreground">{format(new Date(log.timestamp), 'MMM dd, yyyy HH:mm:ss')}</span>
                  </div>
                  <p className="text-sm text-foreground">
                    <span className="font-semibold">Agent:</span> {log.agent_id} <br />
                    <span className="font-semibold">Action:</span> {log.action} <br />
                    {log.target_resource && <><span className="font-semibold">Resource:</span> {log.target_resource} <br /></>}
                    {log.policy_id && <><span className="font-semibold">Policy ID:</span> {log.policy_id} <br /></>}
                    {log.lobster_trap_score !== undefined && <><span className="font-semibold">LT Score:</span> {log.lobster_trap_score.toFixed(2)} <br /></>}
                  </p>
                  {/* You can add more details here, perhaps in an expandable section */}
                </Card>
              ))}
            </ul>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
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

  if (isLoading) return <Card className="p-4"><CardContent>Loading approval requests...</CardContent></Card>;
  if (error) return <Card className="p-4 bg-red-100 border-red-400 text-red-700"><CardContent>Error: {error.message}</CardContent></Card>;

  const getStatusVariant = (status: string) => {
    switch (status) {
      case 'pending': return 'warning';
      case 'approved': return 'success';
      case 'denied': return 'destructive';
      default: return 'secondary';
    }
  }

  return (
    <Card className="shadow-lg rounded-lg overflow-hidden">
      <CardHeader>
        <CardTitle>Approval Requests</CardTitle>
        <CardDescription>Actions awaiting human review and approval.</CardDescription>
      </CardHeader>
      <CardContent className="p-4">
        <ScrollArea className="h-[calc(100vh-320px)] pr-4"> {/* Adjust height dynamically */}
          {data?.length === 0 ? (
            <p className="text-muted-foreground">No approval requests found.</p>
          ) : (
            <ul className="space-y-4">
              {data?.map((request) => (
                <Card key={request.id} className="p-4">
                  <div className="flex justify-between items-start mb-2">
                    <Badge variant={getStatusVariant(request.status)} className="capitalize">{request.status}</Badge>
                    <span className="text-sm text-muted-foreground">{format(new Date(request.timestamp), 'MMM dd, yyyy HH:mm:ss')}</span>
                  </div>
                  <p className="text-sm text-foreground">
                    <span className="font-semibold">Agent:</span> {request.agent_id} <br />
                    <span className="font-semibold">Action:</span> {request.action_type} <br />
                    <span className="font-semibold">Payload Hash:</span> {request.payload_hash.substring(0, 10)}... <br />
                    {request.expires_at && <><span className="font-semibold">Expires:</span> {format(new Date(request.expires_at), 'MMM dd, yyyy HH:mm')} <br /></>}
                    {request.approver_id && <><span className="font-semibold">Approver:</span> {request.approver_id} <br /></>}
                    {request.approval_reason && <><span className="font-semibold">Reason:</span> {request.approval_reason} <br /></>}
                  </p>
                  {request.status === 'pending' && (
                    <div className="mt-3 space-x-2">
                      <Button
                        variant="success" // Assuming a success variant for green button
                        onClick={() => handleApprove(request.id)}
                        disabled={approveMutation.isPending}
                      >
                        Approve
                      </Button>
                      <Button
                        variant="destructive"
                        onClick={() => handleDeny(request.id)}
                        disabled={approveMutation.isPending}
                      >
                        Deny
                      </Button>
                    </div>
                  )}
                </Card>
              ))}
            </ul>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};


ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
);
