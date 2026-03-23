# Palkeoramix decompiler. 

def storage:
  stor1 is mapping of uint256 at storage 1
  stor2 is mapping of uint256 at storage 2

def _fallback(?) payable: # default function
  require calldata.size
  if uint32(call.func_hash) == name():
      require (call.value == 0)
      return 'ChainLink Token'
  if approve(address spender, uint256 amount) == uint32(call.func_hash):
      require (call.value == 0)
      require _param1
      require (_param1 != this.address)
      stor2[caller][address(_param1)] = _param2
      log Approval(
            address owner=_param2,
            address spender=caller,
            uint256 value=_param1)
  else:
      if totalSupply() == uint32(call.func_hash):
          require (call.value == 0)
          return 1000000000 * 10^18
      if transferFrom(address from, address to, uint256 amount) == uint32(call.func_hash):
          require (call.value == 0)
          require address(_param2)
          require (address(_param2) != this.address)
          require _param3 <= stor1[address(_param1)]
          stor1[address(_param1)] -= _param3
          require _param3 + stor1[address(_param2)] >= stor1[address(_param2)]
          stor1[address(_param2)] += _param3
          require _param3 <= stor2[address(_param1)][caller]
          stor2[address(_param1)][caller] -= _param3
          log 0xddf252ad: _param3, _param1, address(_param2)
      else:
          if decimals() == uint32(call.func_hash):
              require (call.value == 0)
              return 18
          if (transferAndCall(address to, uint256 value, bytes data) != uint32(call.func_hash)):
              if decreaseApproval(address _spender, uint256 _subtractedValue) == uint32(call.func_hash):
                  require (call.value == 0)
                  if _param2 <= stor2[caller][address(_param1)]:
                      stor2[caller][address(_param1)] -= _param2
                  else:
                      stor2[caller][address(_param1)] = 0
                  log Approval(
                        address owner=stor2[caller][address(_param1)],
                        address spender=caller,
                        uint256 value=_param1)
              else:
                  if balanceOf(address account) == uint32(call.func_hash):
                      require (call.value == 0)
                      return stor1[address(_param1)]
                  if symbol() == uint32(call.func_hash):
                      require (call.value == 0)
                      return 'LINK'
                  if (transfer(address to, uint256 amount) != uint32(call.func_hash)):
                      if (3611153955 != uint32(call.func_hash)):
                          if allowance(address owner, address spender) == uint32(call.func_hash):
                              require (call.value == 0)
                              return stor2[address(_param1)][address(_param2)]
                          label Node((183, 1, ())) setvars: ()
                          revert
                      require (call.value == 0)
                      require _param2 + stor2[caller][address(_param1)] >= stor2[caller][address(_param1)]
                      stor2[caller][address(_param1)] += _param2
                      log Approval(
                            address owner=(_param2 + stor2[caller][address(_param1)]),
                            address spender=caller,
                            uint256 value=_param1)
                  else:
                      require (call.value == 0)
                      require _param1
                      require (_param1 != this.address)
                      require _param2 <= stor1[caller]
                      stor1[caller] -= _param2
                      require _param2 + stor1[_param1] >= stor1[_param1]
                      stor1[address(_param1)] = _param2 + stor1[_param1]
                      log 0xddf252ad: _param2, caller, _param1
          else:
              require (call.value == 0)
              require _param1
              require (_param1 != this.address)
              require _param2 <= stor1[caller]
              stor1[caller] -= _param2
              require _param2 + stor1[_param1] >= stor1[_param1]
              stor1[address(_param1)] = _param2 + stor1[_param1]
              log 0xddf252ad: _param2, caller, _param1
              log 0xe19260af: _param2, Array(len=_param3.length, data=_param3[all]), caller, _param1
              if _param1.code.length > 0:
                  require _param1.code.length
                  call _param1.onTokenTransfer(address , uint256 , bytes _data) with:
                       gas gas_remaining - 710 wei
                      args caller, _param2, Array(len=_param3.length, data=_param3[all])
                  require ext_call.success
  return 1


