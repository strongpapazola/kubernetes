# Reporting Resources Status

## Ingress Resources

An Ingress resource can have a status that includes the address (an IP address or a DNS name), through which the hosts of that Ingress resource are publicly accessible.
You can see the address in the output of the `kubectl get ingress` command, in the ADDRESS column, as shown below:

```
$ kubectl get ingresses
NAME           HOSTS              ADDRESS           PORTS     AGE
cafe-ingress   cafe.example.com   12.13.23.123      80, 443   2m
```

The Ingress controller must be configured to report an Ingress status:

1. Use the command-line flag `-report-ingress-status`.
2. Define a source for an external address. This can be either of:
    1. A user defined address, specified in the `external-status-address` ConfigMap key.
    2. A Service of the type LoadBalancer configured with an external IP or address and specified by the `-external-service` command-line flag.

See the docs about [ConfigMap keys](/nginx-ingress-controller/configuration/global-configuration/configmap-resource) and [Command-line arguments](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments).

Notes: The Ingress controller does not clear the status of Ingress resources when it is being shut down.

## VirtualServer and VirtualServerRoute Resources

A VirtualServer or VirtualServerRoute resource includes the status field with information about the state of the resource and the IP address, through which the hosts of that resource are publicly accessible.
You can see the status in the output of the `kubectl get virtualservers` or `kubectl get virtualserverroutes` commands as shown below:

```
$ kubectl get virtualservers
  NAME   STATE   HOST                   IP            PORTS      AGE
  cafe   Valid   cafe.example.com       12.13.23.123  [80,443]   34s
```

> Note: If there are multiple addresses, only the first one is shown.

In order to see additional addresses or extra information about the `Status` of the resource, use the following command:
```
$ kubectl describe virtualserver <NAME>
. . . 
Status:
  External Endpoints:
    Ip:        12.13.23.123
    Ports:     [80,443]
  Message:  Configuration for cafe/cafe was added or updated
  Reason:   AddedOrUpdated
  State:    Valid
```

### Status Specification 
The following fields are reported in both VirtualServer and VirtualServerRoute status:

```eval_rst
.. list-table::
   :header-rows: 1

   * - Field
     - Description
     - Type
   * - ``State``
     - Current state of the resource. Can be ``Valid``, ``Warning`` an ``Invalid``. For more information, refer to the ``message`` field.
     - ``string``
   * - ``Reason``
     - The reason of the last update.
     - ``string``
   * - ``Message``
     - Additional information about the state.
     - ``string``
   * - ``ExternalEndpoints``
     - A list of external endpoints for which the hosts of the resource are publicly accessible.
     - `[]externalEndpoint <#externalendpoint>`_
```

The following field is reported in the VirtualServerRoute status only:

```eval_rst
.. list-table::
   :header-rows: 1

   * - Field
     - Description
     - Type
   * - ``ReferencedBy``
     - The VirtualServer that references this VirtualServerRoute. Format is ``namespace/name``
     - ``string``
```

### ExternalEndpoint
```eval_rst
.. list-table::
   :header-rows: 1

   * - Field
     - Description
     - Type
   * - ``IP``
     - The external IP address.
     - ``string``
   * - ``Ports``
     - A list of external ports.
     - ``string``
```

The Ingress controller must be configured to report a VirtualServer or VirtualServerRoute status:

1. If you want the Ingress controller to report the `externalEndpoints`, define a source for an external address (Note: the rest of the fields will be reported without the external address configured). This can be either of:
    1. A user defined address, specified in the `external-status-address` ConfigMap key.
    2. A Service of the type LoadBalancer configured with an external IP or address and specified by the `-external-service` command-line flag.

See the docs about [ConfigMap keys](/nginx-ingress-controller/configuration/global-configuration/configmap-resource) and [Command-line arguments](/nginx-ingress-controller/configuration/global-configuration/command-line-arguments).

Notes: The Ingress controller does not clear the status of VirtualServer and VirtualServerRoute resources when it is being shut down.