//go:build ignore

// Independent affine big.Int oracle for the croc v11.5.3 relay wire format.
// Not used by Cayman at runtime. Run: go run tools/relay_vectors.go
package main

import (
 "crypto/aes"
 "crypto/cipher"
 "crypto/hmac"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "math/big"
)
var prime = integer("28948022309329048855892746252183396360603931420023084536990047309120118726721")
func integer(s string) *big.Int { n,ok:=new(big.Int).SetString(s,10); if !ok {panic(s)}; return n }
type point struct {x,y *big.Int}
func p(x,y string) point {return point{integer(x),integer(y)}}
func mod(x *big.Int) *big.Int {return new(big.Int).Mod(x,prime)}
func add(a,b point) point {
 if a.x==nil{return b};if b.x==nil{return a}
 var numerator,denominator *big.Int
 if a.x.Cmp(b.x)==0 {
  if a.y.Cmp(b.y)!=0 || a.y.Sign()==0 {return point{}}
  numerator=new(big.Int).Mul(big.NewInt(3),new(big.Int).Mul(a.x,a.x))
  denominator=new(big.Int).Mul(big.NewInt(2),a.y)
 } else {
  numerator=new(big.Int).Sub(b.y,a.y); denominator=new(big.Int).Sub(b.x,a.x)
 }
 slope:=mod(new(big.Int).Mul(numerator,new(big.Int).ModInverse(denominator,prime)))
 x:=mod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(slope,slope),a.x),b.x))
 y:=mod(new(big.Int).Sub(new(big.Int).Mul(slope,new(big.Int).Sub(a.x,x)),a.y))
 return point{x,y}
}
func mul(p point,n *big.Int) point {var r point;for i:=n.BitLen()-1;i>=0;i--{r=add(r,r);if n.Bit(i)==1{r=add(r,p)}};return r}
func wire(role int,u,v,x,y point) map[string]any {return map[string]any{"Role":role,"Uᵤ":u.x,"Uᵥ":u.y,"Vᵤ":v.x,"Vᵥ":v.y,"Xᵤ":x.x,"Xᵥ":x.y,"Yᵤ":y.x,"Yᵥ":y.y}}
func main(){
 g:=p("5","12"); u:=p("793136080485469241208656611513609866400481671853","18458907634222644275952014841865282643645472623913459400556233196838128612339");v:=p("1086685267857089638167386722555472967068468061489","19593504966619549205903364028255899745298716108914514072669075231742699650911")
 alpha:=integer("1234567890123456789012345678901234567890");beta:=integer("987654321098765432109876543210987654321")
 weak:=new(big.Int).SetBytes([]byte{1,2,3})
 x:=add(mul(u,weak),mul(g,alpha)); y:=add(mul(v,weak),mul(g,beta));z:=mul(g,new(big.Int).Mul(alpha,beta))
 h:=sha256.New();h.Write([]byte{1,2,3});for _,v:=range []*big.Int{x.x,x.y,y.x,y.y,z.x,z.y}{h.Write(v.Bytes())};key:=h.Sum(nil)
 salt:=[]byte{0,1,2,3,4,5,6,7}; mac:=hmac.New(sha256.New,key);mac.Write(salt);mac.Write([]byte{0,0,0,1});last:=mac.Sum(nil);derived:=append([]byte{},last...)
 for i:=1;i<100;i++{mac.Reset();mac.Write(last);last=mac.Sum(nil);for j:=range derived{derived[j]^=last[j]}}
 block,_:=aes.NewCipher(derived);aead,_:=cipher.NewGCM(block);nonce:=[]byte{0,1,2,3,4,5,6,7,8,9,10,11}; encrypted:=aead.Seal(append([]byte{},nonce...),nonce,[]byte("ok|||127.0.0.1:12345"),nil)
 scalar:=make([]byte,32);alpha.FillBytes(scalar)
 result:=map[string]any{"scalar":hex.EncodeToString(scalar),"client":wire(0,u,v,x,point{}),"server":wire(1,u,v,x,y),"key":hex.EncodeToString(key),"salt":hex.EncodeToString(salt),"derived":hex.EncodeToString(derived),"encrypted_banner":hex.EncodeToString(encrypted)}
 data,_:=json.MarshalIndent(result,"","  ");fmt.Println(string(data))
}
