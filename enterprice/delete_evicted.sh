kubectl delete pod $(kubectl get pod | grep Evicted | cut -d ' ' -f 1)
