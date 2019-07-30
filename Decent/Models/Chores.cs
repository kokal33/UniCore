using System;
using System.ComponentModel.DataAnnotations;

namespace Decent.Models
{
    public class Chores
    {
        [Key]
        public long Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public DateTime CompletionDate { get; set; }
        //Here should be entity automatic date time creation on object
        public DateTime DateCreated { get; set; }
        public DateTime DueDate { get; set; }
        public int State { get; set; }
        public bool Shared { get; set; }
        //TODO: Maybe link a room DB set or something
        public int RoomId { get; set; }
        public int UserId { get; set; }
    }
}
